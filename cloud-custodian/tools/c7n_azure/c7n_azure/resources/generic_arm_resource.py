# Copyright 2019 Microsoft Corporation
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

from c7n_azure.constants import RESOURCE_GROUPS_TYPE
from c7n_azure.provider import resources
from c7n_azure.query import DescribeSource, ResourceQuery
from c7n_azure.resources.arm import ArmResourceManager, arm_resource_types

from c7n.filters.core import Filter, type_schema
from c7n.query import sources
from c7n_azure.utils import ResourceIdParser, is_resource_group_id


class GenericArmResourceQuery(ResourceQuery):

    def filter(self, resource_manager, **params):
        client = resource_manager.get_client()
        results = [r.serialize(True) for r in client.resources.list()]

        resource_groups = [r.serialize(True) for r in client.resource_groups.list()]
        for r in resource_groups:
            r['type'] = RESOURCE_GROUPS_TYPE
        results.extend(resource_groups)

        return results


@sources.register('describe-azure-generic')
class GenericArmDescribeSource(DescribeSource):

    resource_query_factory = GenericArmResourceQuery


@resources.register('armresource')
class GenericArmResource(ArmResourceManager):
    """Azure Arm Resource

    :example:

    This policy will find all ARM resources with the tag 'Tag1' present

    .. code-block:: yaml

        policies
          - name: find-resources-with-Tag1
            resource: azure.armresource
            filters:
              - tag:Tag1: present

    """

    class resource_type(ArmResourceManager.resource_type):
        doc_groups = ['Generic']

        service = 'azure.mgmt.resource'
        client = 'ResourceManagementClient'

        resource_type = 'armresource'
        enable_tag_operations = True
        diagnostic_settings_enabled = False

        default_report_fields = (
            'name',
            'type',
            'location',
            'resourceGroup'
        )

    def get_resources(self, resource_ids):
        client = self.get_client()
        result = []

        for rid in resource_ids:
            resource = None
            if is_resource_group_id(rid):
                resource = client.resource_groups.get(ResourceIdParser.get_resource_group(rid))
                resource.type = RESOURCE_GROUPS_TYPE
            else:
                resource = client.resources.get_by_id(rid, self._session.resource_api_version(rid))
            result.append(resource)

        return self.augment([r.serialize(True) for r in result])

    def tag_operation_enabled(self, resource_type):
        if resource_type.lower() in arm_resource_types:
            return arm_resource_types[resource_type.lower()].enable_tag_operations
        return False

    @property
    def source_type(self):
        return self.data.get('source', 'describe-azure-generic')


@GenericArmResource.filter_registry.register('resource-type')
class ResourceTypeFilter(Filter):
    schema = type_schema('resource-type',
                         required=['values'],
                         values={'type': 'array', 'items': {'type': 'string'}})

    def __init__(self, data, manager=None):
        super(ResourceTypeFilter, self).__init__(data, manager)
        self.allowed_types = [t.lower() for t in self.data['values']]

    def process(self, resources, event=None):
        result = []
        for r in resources:
            if r['type'].lower() in self.allowed_types:
                result.append(r)

        return result
