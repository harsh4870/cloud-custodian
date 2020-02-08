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

from c7n_azure.provider import resources
from c7n_azure.resources.arm import ArmResourceManager


@resources.register('databricks')
class Databricks(ArmResourceManager):
    """Databricks Resource

    :example:

    Returns all databricks named my-test-databricks

    .. code-block:: yaml

        policies:
          - name: get-databricks
            resource: azure.databricks
            filters:
              - type: value
                key: name
                op: eq
                value: my-test-databricks

    """

    class resource_type(ArmResourceManager.resource_type):
        doc_groups = ['AI + Machine Learning']

        service = 'azure.mgmt.databricks.databricks_client'
        client = 'DatabricksClient'
        enum_spec = ('workspaces', 'list_by_subscription', None)
        default_report_fields = (
            'name',
            'location',
            'resourceGroup',
            'sku.name'
        )
        resource_type = 'Microsoft.Databricks/workspaces'
