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
import re

from c7n_gcp.actions import MethodAction
from c7n_gcp.query import QueryResourceManager, TypeInfo

from c7n_gcp.provider import resources
from c7n.utils import type_schema


@resources.register('vpc')
class Network(QueryResourceManager):
    """GCP resource: https://cloud.google.com/compute/docs/reference/rest/v1/networks
    """
    class resource_type(TypeInfo):
        service = 'compute'
        version = 'v1'
        component = 'networks'
        scope_template = "projects/{}/global/networks"
        id = "name"


@resources.register('subnet')
class Subnet(QueryResourceManager):
    """GCP resource: https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks
    """
    class resource_type(TypeInfo):
        service = 'compute'
        version = 'v1'
        component = 'subnetworks'
        enum_spec = ('aggregatedList', 'items.*.subnetworks[]', None)
        id = "name"

        @staticmethod
        def get(client, resource_info):
            return client.execute_query(
                'get', {'project': resource_info['project_id'],
                        'region': resource_info['location'],
                        'subnetwork': resource_info['subnetwork_name']})


class SubnetAction(MethodAction):

    path_param_re = re.compile(
        '.*?/projects/(.*?)/regions/(.*?)/subnetworks/(.*)')

    def get_resource_params(self, model, resource):
        project, region, subnet = self.path_param_re.match(
            resource['selfLink']).groups()
        return {'project': project, 'region': region, 'subnetwork': subnet}


@Subnet.action_registry.register('set-flow-log')
class SetFlowLog(SubnetAction):
    """Enable vpc flow logs on a subnet.

    :example: Enable flow logs on all subnets

    .. yaml:

     policies:
       - name: flow-active
         resource: gcp.subnet
         filters:
          - enableFlowLogs: empty
         actions:
          - set-flow-log

    """

    schema = type_schema(
        'set-flow-log',
        state={'type': 'boolean', 'default': True})
    method_spec = {'op': 'patch'}

    def get_resource_params(self, m, r):
        params = super(SetFlowLog, self).get_resource_params(m, r)
        params['body'] = dict(r)
        params['body']['enableFlowLogs'] = self.data.get('state', True)
        return params


@Subnet.action_registry.register('set-private-api')
class SetGcpPrivateAccess(SubnetAction):
    """Enable/Disable GCP Private IP Access for a subnet"""

    schema = type_schema(
        'set-gcp-private',
        state={'type': 'boolean', 'default': True})
    method_spec = {'op': 'setPrivateIpGoogleAccess'}

    def get_resource_params(self, m, r):
        params = super(SetGcpPrivateAccess, self).get_resource_params(m, r)
        params['body'] = {
            'privateIpGoogleAccess': self.data.get('state', True)}
        return params


@resources.register('firewall')
class Firewall(QueryResourceManager):
    """GCP resource: https://cloud.google.com/compute/docs/reference/rest/v1/firewalls
    """
    class resource_type(TypeInfo):
        service = 'compute'
        version = 'v1'
        component = 'firewalls'
        id = "name"

        @staticmethod
        def get(client, resource_info):
            return client.execute_query(
                'get', {'project': resource_info['project_id'],
                        'firewall': resource_info['resourceName'].rsplit('/', 1)[-1]})


@resources.register('router')
class Router(QueryResourceManager):
    """GCP resource: https://cloud.google.com/compute/docs/reference/rest/v1/routers
    """
    class resource_type(TypeInfo):
        service = 'compute'
        version = 'v1'
        component = 'routers'
        enum_spec = ('aggregatedList', 'items.*.routers[]', None)
        id = 'name'

        @staticmethod
        def get(client, resource_info):
            return client.execute_command(
                'get', {'project': resource_info['project_id'],
                        'region': resource_info['region'],
                        'router': resource_info['resourceName'].rsplit('/', 1)[-1]})


@Router.action_registry.register('delete')
class DeleteRouter(MethodAction):
    """`Deletes <https://cloud.google.com/compute/docs/reference/rest/v1/routers/delete>`_ a router

    :Example:

    .. code-block:: yaml

        policies:
          - name: gcp-network-unattached-routers
            description: Deletes unattached Cloud Routers
            resource: gcp.router
            filters:
               - type: value
                 key: interfaces
                 value: absent
            actions:
               - delete
    """

    schema = type_schema('delete')
    method_spec = {'op': 'delete'}
    path_param_re = re.compile('.*?/projects/(.*?)/regions/(.*?)/routers/(.*)')

    def get_resource_params(self, m, r):
        project, region, router = self.path_param_re.match(r['selfLink']).groups()
        return {'project': project, 'region': region, 'router': router}


@resources.register('route')
class Route(QueryResourceManager):
    """GCP resource: https://cloud.google.com/compute/docs/reference/rest/v1/routes
    """
    class resource_type(TypeInfo):
        service = 'compute'
        version = 'v1'
        component = 'routes'
        enum_spec = ('list', 'items[]', None)
        id = 'name'

        @staticmethod
        def get(client, resource_info):
            return client.execute_command(
                'get', {'project': resource_info['project_id'],
                        'route': resource_info['resourceName'].rsplit('/', 1)[-1]})


@resources.register('interconnect')
class Interconnect(QueryResourceManager):
    """GCP resource: https://cloud.google.com/compute/docs/reference/rest/v1/interconnects
    """
    class resource_type(TypeInfo):
        service = 'compute'
        version = 'v1'
        component = 'interconnects'
        enum_spec = ('list', 'items[]', None)
        id = 'name'

        @staticmethod
        def get(client, resource_info):
            return client.execute_command(
                'get', {'project': resource_info['project_id'],
                        'interconnect': resource_info['resourceName'].rsplit('/', 1)[-1]})


@resources.register('interconnect-attachment')
class InterconnectAttachment(QueryResourceManager):
    """GCP resource: https://cloud.google.com/compute/docs/reference/rest/v1/interconnectAttachments
    """
    class resource_type(TypeInfo):
        service = 'compute'
        version = 'v1'
        component = 'interconnectAttachments'
        enum_spec = ('aggregatedList', 'items.*.interconnectAttachments[]', None)
        id = 'name'

        @staticmethod
        def get(client, resource_info):
            project, region, name = re.match(
                'projects/(.*?)/regions/(.*?)/interconnectAttachments/(.*?)',
                resource_info['resourceName']).groups()

            return client.execute_command(
                'get', {'project': project,
                        'interconnectAttachment': name,
                        'region': region})
