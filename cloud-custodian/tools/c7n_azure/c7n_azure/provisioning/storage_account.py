from msrestazure.azure_exceptions import CloudError

from c7n_azure.provisioning.deployment_unit import DeploymentUnit
from c7n_azure.provisioning.resource_group import ResourceGroupUnit


class StorageAccountUnit(DeploymentUnit):

    def __init__(self):
        super(StorageAccountUnit, self).__init__(
            'azure.mgmt.storage.StorageManagementClient')
        self.type = "Storage Account"

    def _get(self, params):
        try:
            return self.client.storage_accounts.get_properties(params['resource_group_name'],
                                                               params['name'])
        except CloudError:
            return None

    def _provision(self, params):
        rg_unit = ResourceGroupUnit()
        rg_unit.provision_if_not_exists({'name': params['resource_group_name'],
                                         'location': params['location']})

        sa_params = {'sku': {'name': 'Standard_LRS'},
                    'kind': 'Storage',
                    'location': params['location']}
        return self.client.storage_accounts.create(params['resource_group_name'],
                                                   params['name'],
                                                   sa_params).result()
