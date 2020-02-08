# Copyright 2017-2018 Capital One Services, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import jmespath
import json
import logging
import six

from googleapiclient.errors import HttpError

from c7n.actions import ActionRegistry
from c7n.filters import FilterRegistry
from c7n.manager import ResourceManager
from c7n.query import sources, MaxResourceLimit
from c7n.utils import local_session


log = logging.getLogger('c7n_gcp.query')


class ResourceQuery(object):

    def __init__(self, session_factory):
        self.session_factory = session_factory

    def filter(self, resource_manager, **params):
        m = resource_manager.resource_type
        session = local_session(self.session_factory)
        client = session.client(
            m.service, m.version, m.component)

        # depends on resource scope
        if m.scope in ('project', 'zone'):
            project = session.get_default_project()
            if m.scope_template:
                project = m.scope_template.format(project)
            if m.scope_key:
                params[m.scope_key] = project
            else:
                params['project'] = project

        if m.scope == 'zone':
            if session.get_default_zone():
                params['zone'] = session.get_default_zone()

        enum_op, path, extra_args = m.enum_spec
        if extra_args:
            params.update(extra_args)
        return self._invoke_client_enum(
            client, enum_op, params, path)

    def _invoke_client_enum(self, client, enum_op, params, path):
        if client.supports_pagination(enum_op):
            results = []
            for page in client.execute_paged_query(enum_op, params):
                page_items = jmespath.search(path, page)
                if page_items:
                    results.extend(page_items)
            return results
        else:
            return jmespath.search(path,
                client.execute_query(enum_op, verb_arguments=params))


@sources.register('describe-gcp')
class DescribeSource(object):

    def __init__(self, manager):
        self.manager = manager
        self.query = ResourceQuery(manager.session_factory)

    def get_resources(self, query):
        if query is None:
            query = {}
        return self.query.filter(self.manager, **query)

    def get_permissions(self):
        return ()

    def augment(self, resources):
        return resources


class QueryMeta(type):
    """metaclass to have consistent action/filter registry for new resources."""
    def __new__(cls, name, parents, attrs):
        if 'filter_registry' not in attrs:
            attrs['filter_registry'] = FilterRegistry(
                '%s.filters' % name.lower())
        if 'action_registry' not in attrs:
            attrs['action_registry'] = ActionRegistry(
                '%s.actions' % name.lower())

        return super(QueryMeta, cls).__new__(cls, name, parents, attrs)


@six.add_metaclass(QueryMeta)
class QueryResourceManager(ResourceManager):

    def __init__(self, data, options):
        super(QueryResourceManager, self).__init__(data, options)
        self.source = self.get_source(self.source_type)

    def get_permissions(self):
        return ()

    def get_source(self, source_type):
        return sources.get(source_type)(self)

    def get_client(self):
        return local_session(self.session_factory).client(
            self.resource_type.service,
            self.resource_type.version,
            self.resource_type.component)

    def get_model(self):
        return self.resource_type

    def get_cache_key(self, query):
        return {'source_type': self.source_type, 'query': query,
                'service': self.resource_type.service,
                'version': self.resource_type.version,
                'component': self.resource_type.component}

    def get_resource(self, resource_info):
        return self.resource_type.get(self.get_client(), resource_info)

    @property
    def source_type(self):
        return self.data.get('source', 'describe-gcp')

    def get_resource_query(self):
        if 'query' in self.data:
            return {'filter': self.data.get('query')}

    def resources(self, query=None):
        q = query or self.get_resource_query()
        key = self.get_cache_key(q)
        resources = self._fetch_resources(q)
        self._cache.save(key, resources)

        resource_count = len(resources)
        resources = self.filter_resources(resources)

        # Check if we're out of a policies execution limits.
        if self.data == self.ctx.policy.data:
            self.check_resource_limit(len(resources), resource_count)
        return resources

    def check_resource_limit(self, selection_count, population_count):
        """Check if policy's execution affects more resources then its limit.
        """
        p = self.ctx.policy
        max_resource_limits = MaxResourceLimit(p, selection_count, population_count)
        return max_resource_limits.check_resource_limits()

    def _fetch_resources(self, query):
        try:
            return self.augment(self.source.get_resources(query)) or []
        except HttpError as e:
            error = extract_error(e)
            if error is None:
                raise
            elif error == 'accessNotConfigured':
                log.warning(
                    "Resource:%s not available -> Service:%s not enabled on %s",
                    self.type,
                    self.resource_type.service,
                    local_session(self.session_factory).get_default_project())
                return []
            raise

    def augment(self, resources):
        return resources


class ChildResourceManager(QueryResourceManager):

    def get_resource(self, resource_info):
        child_instance = super(ChildResourceManager, self).get_resource(resource_info)

        parent_resource = self.resource_type.parent_spec['resource']
        parent_instance = self.get_resource_manager(parent_resource).get_resource(
            self._get_parent_resource_info(child_instance)
        )

        annotation_key = self.resource_type.get_parent_annotation_key()
        child_instance[annotation_key] = parent_instance

        return child_instance

    def _fetch_resources(self, query):
        if not query:
            query = {}

        resources = []
        annotation_key = self.resource_type.get_parent_annotation_key()
        parent_query = self.get_parent_resource_query()
        parent_resource_manager = self.get_resource_manager(
            resource_type=self.resource_type.parent_spec['resource'],
            data=({'query': parent_query} if parent_query else {})
        )

        for parent_instance in parent_resource_manager.resources():
            query.update(self._get_child_enum_args(parent_instance))
            children = super(ChildResourceManager, self)._fetch_resources(query)

            for child_instance in children:
                child_instance[annotation_key] = parent_instance

            resources.extend(children)

        return resources

    def _get_parent_resource_info(self, child_instance):
        mappings = self.resource_type.parent_spec['parent_get_params']
        return self._extract_fields(child_instance, mappings)

    def _get_child_enum_args(self, parent_instance):
        mappings = self.resource_type.parent_spec['child_enum_params']
        return self._extract_fields(parent_instance, mappings)

    def get_parent_resource_query(self):
        parent_spec = self.resource_type.parent_spec
        enabled = parent_spec['use_child_query'] if 'use_child_query' in parent_spec else False
        if enabled and 'query' in self.data:
            return self.data.get('query')

    @staticmethod
    def _extract_fields(source, mappings):
        result = {}

        for mapping in mappings:
            result[mapping[1]] = jmespath.search(mapping[0], source)

        return result


class TypeMeta(type):

    def __repr__(cls):
        return "<TypeInfo service:%s component:%s scope:%s version:%s>" % (
            cls.service,
            cls.component,
            cls.scope,
            cls.version)


@six.add_metaclass(TypeMeta)
class TypeInfo(object):

    # api client construction information
    service = None
    version = None
    component = None

    # resource enumeration parameters

    scope = 'project'
    enum_spec = ('list', 'items[]', None)
    # ie. when project is passed instead as parent
    scope_key = None
    # custom formatting for scope key
    scope_template = None

    # individual resource retrieval method, for serverless policies.
    get = None
    # for get methods that require the full event payload
    get_requires_event = False

    labels = False
    labels_op = 'setLabels'


class ChildTypeInfo(TypeInfo):

    parent_spec = None

    @classmethod
    def get_parent_annotation_key(cls):
        parent_resource = cls.parent_spec['resource']
        return 'c7n:{}'.format(parent_resource)


ERROR_REASON = jmespath.compile('error.errors[0].reason')


def extract_error(e):

    try:
        edata = json.loads(e.content)
    except Exception:
        return None
    return ERROR_REASON.search(edata)


class GcpLocation(object):
    """
    The `_locations` dict is formed by the string keys representing locations taken from
    `KMS <https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations/list>`_ and
    `App Engine <https://cloud.google.com/appengine/docs/admin-api/reference/rest/v1
    /apps.locations/list>`_ and list values containing the string names of the services
    the locations are available for.
    """
    _locations = {'eur4': ['kms'],
                  'global': ['kms'],
                  'europe-west4': ['kms'],
                  'asia-east2': ['appengine', 'kms'],
                  'asia-east1': ['kms'],
                  'asia': ['kms'],
                  'europe-north1': ['kms'],
                  'us-central1': ['kms'],
                  'nam4': ['kms'],
                  'asia-southeast1': ['kms'],
                  'europe': ['kms'],
                  'australia-southeast1': ['appengine', 'kms'],
                  'us-central': ['appengine'],
                  'asia-south1': ['appengine', 'kms'],
                  'us-west1': ['kms'],
                  'us-west2': ['appengine', 'kms'],
                  'asia-northeast2': ['appengine', 'kms'],
                  'asia-northeast1': ['appengine', 'kms'],
                  'europe-west2': ['appengine', 'kms'],
                  'europe-west3': ['appengine', 'kms'],
                  'us-east4': ['appengine', 'kms'],
                  'europe-west1': ['kms'],
                  'europe-west6': ['appengine', 'kms'],
                  'us': ['kms'],
                  'us-east1': ['appengine', 'kms'],
                  'northamerica-northeast1': ['appengine', 'kms'],
                  'europe-west': ['appengine'],
                  'southamerica-east1': ['appengine', 'kms']}

    @classmethod
    def get_service_locations(cls, service):
        """
        Returns a list of the locations that have a given service in associated value lists.

        :param service: a string representing the name of a service locations are queried for
        """
        return [location for location in GcpLocation._locations
                if service in GcpLocation._locations[location]]
