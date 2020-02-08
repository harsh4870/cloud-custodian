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
from c7n_azure.resources.arm import ChildResourceManager
from c7n_azure.query import ChildTypeInfo


@resources.register('postgresql-database')
class PostgresqlDatabase(ChildResourceManager):
    """PostgreSQL Database Resource

    The ``azure.postgresql-database`` resource is a child resource of the PostgreSQL Server
    resource, and the PostgreSQL Server parent id is available as the ``c7n:parent-id`` property.

    :example:

    Finds all PostgreSQL Databases that are children of PostgreSQL Servers with the
    environment:dev tag

    .. code-block:: yaml

        policies:
          - name: find-all-dev-postgresql-databases
            resource: azure.postgresql-database
            filters:
              - type: parent
                filter:
                  type: value
                  key: tags.environment
                  value: dev
    """

    class resource_type(ChildTypeInfo):
        doc_groups = ['Databases']

        service = 'azure.mgmt.rdbms.postgresql'
        client = 'PostgreSQLManagementClient'
        enum_spec = ('databases', 'list_by_server', None)
        parent_manager_name = 'postgresql-server'
        default_report_fields = (
            'name',
            '"c7n:parent-id"'
        )

        @classmethod
        def extra_args(cls, parent_resource):
            return {'resource_group_name': parent_resource['resourceGroup'],
                    'server_name': parent_resource['name']}
