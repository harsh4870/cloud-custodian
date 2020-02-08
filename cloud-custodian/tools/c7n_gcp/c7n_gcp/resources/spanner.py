# Copyright 2019 Capital One Services, LLC
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
from c7n.utils import type_schema
from c7n_gcp.actions import MethodAction, SetIamPolicy
from c7n_gcp.provider import resources
from c7n_gcp.query import QueryResourceManager, TypeInfo, ChildTypeInfo, ChildResourceManager


@resources.register('spanner-instance')
class SpannerInstance(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'spanner'
        version = 'v1'
        component = 'projects.instances'
        enum_spec = ('list', 'instances[]', None)
        scope_key = 'parent'
        scope_template = 'projects/{}'
        id = 'name'

        labels = True
        labels_op = 'patch'

        @staticmethod
        def get(client, resource_info):
            return client.execute_command(
                'get', {'name': resource_info['resourceName']}
            )

        @staticmethod
        def get_label_params(resource, all_labels):
            return {'name': resource['name'],
                    'body': {
                        'instance': {
                            'labels': all_labels
                        },
                        'field_mask': ', '.join(['labels'])}}


@SpannerInstance.action_registry.register('delete')
class SpannerInstanceDelete(MethodAction):
    """The action is used for spanner instances delete.

    GCP action is https://cloud.google.com/spanner/docs/reference/rest/v1/projects.instances/delete

    :Example:

    .. code-block:: yaml

        policies:
          - name: gcp-spanner-instances-delete
            resource: gcp.spanner-instance
            filters:
              - type: value
                key: nodeCount
                op: gte
                value: 2
            actions:
              - type: delete
    """
    schema = type_schema('delete')
    method_spec = {'op': 'delete'}

    def get_resource_params(self, model, resource):
        return {'name': resource['name']}


@SpannerInstance.action_registry.register('set')
class SpannerInstancePatch(MethodAction):
    """The action is used for spanner instances nodeCount patch.

    GCP action is https://cloud.google.com/spanner/docs/reference/rest/v1/projects.instances/patch

    :Example:

    .. code-block:: yaml

        policies:
          - name: gcp-spanner-instances-change-node-count
            resource: gcp.spanner-instance
            filters:
              - type: value
                key: nodeCount
                op: gte
                value: 2
            actions:
              - type: set
                nodeCount: 1
    """
    schema = type_schema('set', required=['nodeCount'],
                         **{'nodeCount': {'type': 'number'}})
    method_spec = {'op': 'patch'}

    def get_resource_params(self, model, resource):
        result = {'name': resource['name'],
                  'body': {
                      'instance': {
                          'nodeCount': self.data['nodeCount']
                      },
                      'field_mask': ', '.join(['nodeCount'])}
                  }
        return result


SpannerInstance.action_registry.register('set-iam-policy', SetIamPolicy)


@resources.register('spanner-database-instance')
class SpannerDatabaseInstance(ChildResourceManager):
    """GCP resource:
    https://cloud.google.com/spanner/docs/reference/rest/v1/projects.instances.databases
    """
    def _get_parent_resource_info(self, child_instance):
        resource_name = None
        if child_instance['name'] is not None:
            resource_names = child_instance['name'].split('/databases')
            if len(resource_names) > 0:
                resource_name = resource_names[0]
        return {
            'resourceName': resource_name
        }

    class resource_type(ChildTypeInfo):
        service = 'spanner'
        version = 'v1'
        component = 'projects.instances.databases'
        enum_spec = ('list', 'databases[]', None)
        id = 'name'
        scope = None
        parent_spec = {
            'resource': 'spanner-instance',
            'child_enum_params': [
                ('name', 'parent')
            ]
        }

        @staticmethod
        def get(client, resource_info):
            return client.execute_command(
                'get', {
                    'name': resource_info['resourceName']}
            )


SpannerDatabaseInstance.action_registry.register('set-iam-policy', SetIamPolicy)


@SpannerDatabaseInstance.action_registry.register('delete')
class SpannerDatabaseInstanceDropDatabase(MethodAction):
    """The action is used for databases deleting.

    GCP action is https://cloud.google.com/spanner/docs
        /reference/rest/v1/projects.instances.databases/dropDatabase.

    :Example:

    .. code-block:: yaml

        policies:
          - name: gcp-spanner-instance-databases-delete
            resource: gcp.spanner-database-instance
            filters:
              - type: value
                key: name
                op: contains
                value: dev
            actions:
              - type: delete
    """
    schema = type_schema('dropDatabase', **{'type': {'enum': ['delete']}})
    method_spec = {'op': 'dropDatabase'}

    def get_resource_params(self, model, resource):
        return {'database': resource['name']}
