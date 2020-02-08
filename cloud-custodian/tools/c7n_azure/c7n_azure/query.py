# Copyright 2018 Capital One Services, LLC
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

import logging
try:
    from collections.abc import Iterable
except ImportError:
    from collections import Iterable

import six
from c7n_azure import constants
from c7n_azure.actions.logic_app import LogicAppAction
from azure.mgmt.resourcegraph.models import QueryRequest
from c7n_azure.actions.notify import Notify
from c7n_azure.filters import ParentFilter
from c7n_azure.provider import resources

from c7n.actions import ActionRegistry
from c7n.exceptions import PolicyValidationError
from c7n.filters import FilterRegistry
from c7n.manager import ResourceManager
from c7n.query import sources, MaxResourceLimit
from c7n.utils import local_session

log = logging.getLogger('custodian.azure.query')


class ResourceQuery(object):

    def __init__(self, session_factory):
        self.session_factory = session_factory

    def filter(self, resource_manager, **params):
        m = resource_manager.resource_type
        enum_op, list_op, extra_args = m.enum_spec

        if extra_args:
            params.update(extra_args)

        params.update(m.extra_args(resource_manager))

        try:
            op = getattr(getattr(resource_manager.get_client(), enum_op), list_op)
            result = op(**params)

            if isinstance(result, Iterable):
                return [r.serialize(True) for r in result]
            elif hasattr(result, 'value'):
                return [r.serialize(True) for r in result.value]
        except Exception as e:
            log.error("Failed to query resource.\n"
                      "Type: azure.{0}.\n"
                      "Error: {1}".format(resource_manager.type, e))
            raise

        raise TypeError("Enumerating resources resulted in a return"
                        "value which could not be iterated.")

    @staticmethod
    def resolve(resource_type):
        if not isinstance(resource_type, type):
            raise ValueError(resource_type)
        else:
            m = resource_type
        return m


@sources.register('describe-azure')
class DescribeSource(object):
    resource_query_factory = ResourceQuery

    def __init__(self, manager):
        self.manager = manager
        self.query = self.resource_query_factory(self.manager.session_factory)

    def validate(self):
        pass

    def get_resources(self, query):
        return self.query.filter(self.manager)

    def get_permissions(self):
        return ()

    def augment(self, resources):
        return resources


@sources.register('resource-graph')
class ResourceGraphSource(object):

    def __init__(self, manager):
        self.manager = manager

    def validate(self):
        if not hasattr(self.manager.resource_type, 'resource_type'):
            raise PolicyValidationError(
                "%s is not supported with the Azure Resource Graph source."
                % self.manager.data['resource'])

    def get_resources(self, _):
        log.warning('The Azure Resource Graph source '
                    'should not be used in production scenarios at this time.')

        session = self.manager.get_session()
        client = session.client('azure.mgmt.resourcegraph.ResourceGraphClient')

        # empty scope will return all resource
        query_scope = ""
        if self.manager.resource_type.resource_type != 'armresource':
            query_scope = "where type =~ '%s'" % self.manager.resource_type.resource_type

        query = QueryRequest(
            query=query_scope,
            subscriptions=[session.get_subscription_id()]
        )
        res = client.resources(query)
        cols = [c['name'] for c in res.data['columns']]
        data = [dict(zip(cols, r)) for r in res.data['rows']]
        return data

    def get_permissions(self):
        return ()

    def augment(self, resources):
        return resources


class ChildResourceQuery(ResourceQuery):
    """A resource query for resources that must be queried with parent information.
    Several resource types can only be queried in the context of their
    parents identifiers. ie. SQL and Cosmos databases
    """

    def filter(self, resource_manager, **params):
        """Query a set of resources."""
        m = self.resolve(resource_manager.resource_type)  # type: ChildTypeInfo

        parents = resource_manager.get_parent_manager()

        # Have to query separately for each parent's children.
        results = []
        for parent in parents.resources():
            try:
                subset = resource_manager.enumerate_resources(parent, m, **params)

                if subset:
                    # If required, append parent resource ID to all child resources
                    if m.annotate_parent:
                        for r in subset:
                            r[m.parent_key] = parent[parents.resource_type.id]

                    results.extend(subset)

            except Exception as e:
                log.warning('Child enumeration failed for {0}. {1}'
                            .format(parent[parents.resource_type.id], e))
                if m.raise_on_exception:
                    raise e

        return results


@sources.register('describe-child-azure')
class ChildDescribeSource(DescribeSource):
    resource_query_factory = ChildResourceQuery


class TypeMeta(type):

    def __repr__(cls):
        return "<Type info service:%s client: %s>" % (
            cls.service,
            cls.client)


@six.add_metaclass(TypeMeta)
class TypeInfo(object):
    doc_groups = None

    """api client construction information"""
    service = ''
    client = ''

    # Default id field, resources should override if different (used for meta filters, report etc)
    id = 'id'

    resource = constants.RESOURCE_ACTIVE_DIRECTORY

    @classmethod
    def extra_args(cls, resource_manager):
        return {}


@six.add_metaclass(TypeMeta)
class ChildTypeInfo(TypeInfo):
    """api client construction information for child resources"""
    parent_manager_name = ''
    annotate_parent = True
    raise_on_exception = True
    parent_key = 'c7n:parent-id'

    @classmethod
    def extra_args(cls, parent_resource):
        return {}


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
    class resource_type(TypeInfo):
        pass

    def __init__(self, data, options):
        super(QueryResourceManager, self).__init__(data, options)
        self.source = self.get_source(self.source_type)
        self._session = None

    def augment(self, resources):
        return resources

    def get_permissions(self):
        return ()

    def get_source(self, source_type):
        return sources.get(source_type)(self)

    def get_session(self):
        if self._session is None:
            self._session = local_session(self.session_factory)
        return self._session

    def get_client(self, service=None):
        if not service:
            return self.get_session().client(
                "%s.%s" % (self.resource_type.service, self.resource_type.client))
        return self.get_session().client(service)

    def get_cache_key(self, query):
        return {'source_type': self.source_type, 'query': query}

    @classmethod
    def get_model(cls):
        return ResourceQuery.resolve(cls.resource_type)

    @property
    def source_type(self):
        return self.data.get('source', 'describe-azure')

    def resources(self, query=None):
        cache_key = self.get_cache_key(query)

        resources = None
        if self._cache.load():
            resources = self._cache.get(cache_key)
            if resources is not None:
                self.log.debug("Using cached %s: %d" % (
                    "%s.%s" % (self.__class__.__module__,
                               self.__class__.__name__),
                    len(resources)))

        if resources is None:
            resources = self.augment(self.source.get_resources(query))
            self._cache.save(cache_key, resources)

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

    def get_resources(self, resource_ids, **params):
        resource_client = self.get_client()
        m = self.resource_type
        get_client, get_op, extra_args = m.get_spec

        if extra_args:
            params.update(extra_args)

        op = getattr(getattr(resource_client, get_client), get_op)
        data = [
            op(rid, **params)
            for rid in resource_ids
        ]
        return [r.serialize(True) for r in data]

    @staticmethod
    def register_actions_and_filters(registry, resource_class):
        resource_class.action_registry.register('notify', Notify)
        if 'logic-app' not in resource_class.action_registry:
            resource_class.action_registry.register('logic-app', LogicAppAction)

    def validate(self):
        self.source.validate()


@six.add_metaclass(QueryMeta)
class ChildResourceManager(QueryResourceManager):
    child_source = 'describe-child-azure'
    parent_manager = None

    @property
    def source_type(self):
        source = self.data.get('source', self.child_source)
        if source == 'describe':
            source = self.child_source
        return source

    def get_parent_manager(self):
        if not self.parent_manager:
            self.parent_manager = self.get_resource_manager(self.resource_type.parent_manager_name)

        return self.parent_manager

    def get_session(self):
        if self._session is None:
            session = super(ChildResourceManager, self).get_session()
            if self.resource_type.resource != constants.RESOURCE_ACTIVE_DIRECTORY:
                session = session.get_session_for_resource(self.resource_type.resource)
            self._session = session

        return self._session

    def enumerate_resources(self, parent_resource, type_info, **params):
        client = self.get_client()

        enum_op, list_op, extra_args = self.resource_type.enum_spec

        # There are 2 types of extra_args:
        #   - static values stored in 'extra_args' dict (e.g. some type)
        #   - dynamic values are retrieved via 'extra_args' method (e.g. parent name)
        if extra_args:
            params.update({key: extra_args[key](parent_resource) for key in extra_args.keys()})

        params.update(type_info.extra_args(parent_resource))

        # Some resources might not have enum_op piece (non-arm resources)
        if enum_op:
            op = getattr(getattr(client, enum_op), list_op)
        else:
            op = getattr(client, list_op)

        result = op(**params)

        if isinstance(result, Iterable):
            return [r.serialize(True) for r in result]
        elif hasattr(result, 'value'):
            return [r.serialize(True) for r in result.value]

        raise TypeError("Enumerating resources resulted in a return"
                        "value which could not be iterated.")

    @staticmethod
    def register_child_specific(registry, resource_class):
        if not issubclass(resource_class, ChildResourceManager):
            return

        # If Child Resource doesn't annotate parent, there is no way to filter based on
        # parent properties.
        if resource_class.resource_type.annotate_parent:
            resource_class.filter_registry.register('parent', ParentFilter)


resources.subscribe(QueryResourceManager.register_actions_and_filters)
resources.subscribe(ChildResourceManager.register_child_specific)
