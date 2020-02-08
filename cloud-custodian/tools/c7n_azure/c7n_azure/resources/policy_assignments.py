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

from c7n_azure.provider import resources
from c7n_azure.resources.arm import ArmResourceManager


@resources.register('policyassignments')
class PolicyAssignments(ArmResourceManager):
    """Policy Assignment Resource

    :example:

    This policy will find all policy assignments named 'test-assignment' and delete them.

    .. code-block:: yaml

      policies:
        - name: remove-test-assignments
          resource: azure.policyassignments
          filters:
            - type: value
              key: properties.displayName
              value_type: normalize
              op: eq
              value: 'test-assignment'
          actions:
            - type: delete

    """

    class resource_type(ArmResourceManager.resource_type):
        doc_groups = ['Subscription', 'Generic']

        service = 'azure.mgmt.resource.policy'
        client = 'PolicyClient'
        enum_spec = ('policy_assignments', 'list', None)
        resource_type = 'Microsoft.Authorization/policyAssignments'
        default_report_fields = (
            'name',
            'resourceGroup'
        )
