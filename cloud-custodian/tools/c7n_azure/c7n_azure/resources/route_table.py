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

from c7n_azure.provider import resources
from c7n_azure.resources.arm import ArmResourceManager


@resources.register('routetable')
class RouteTable(ArmResourceManager):
    """Route Table Resource

    :example:

    Finds all Route Tables in the subscription.

    .. code-block:: yaml

        policies:
            - name: find-all-route-tables
              resource: azure.routetable

    """

    class resource_type(ArmResourceManager.resource_type):
        doc_groups = ['Networking']

        service = 'azure.mgmt.network'
        client = 'NetworkManagementClient'
        enum_spec = ('route_tables', 'list_all', None)
        default_report_fields = (
            'name',
            'location',
            'resourceGroup',
            'properties.subnets[].id'
        )
        resource_type = 'Microsoft.Network/routeTables'
