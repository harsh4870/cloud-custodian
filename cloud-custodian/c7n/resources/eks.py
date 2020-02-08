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
from __future__ import absolute_import, division, print_function, unicode_literals

from c7n.actions import Action
from c7n.filters.vpc import SecurityGroupFilter, SubnetFilter, VpcFilter
from c7n.manager import resources
from c7n import tags
from c7n.query import QueryResourceManager, TypeInfo
from c7n.utils import local_session, type_schema

from .aws import shape_validate


@resources.register('eks')
class EKS(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'eks'
        enum_spec = ('list_clusters', 'clusters', None)
        arn = 'arn'
        arn_type = 'cluster'
        detail_spec = ('describe_cluster', 'name', None, 'cluster')
        id = name = 'name'
        date = 'createdAt'

    def augment(self, resources):
        resources = super(EKS, self).augment(resources)
        for r in resources:
            if 'tags' not in r:
                continue
            r['Tags'] = [{'Key': k, 'Value': v} for k, v in r['tags'].items()]
        return resources


@EKS.filter_registry.register('subnet')
class EKSSubnetFilter(SubnetFilter):

    RelatedIdsExpression = "resourcesVpcConfig.subnetIds[]"


@EKS.filter_registry.register('security-group')
class EKSSGFilter(SecurityGroupFilter):

    RelatedIdsExpression = "resourcesVpcConfig.securityGroupIds[]"


@EKS.filter_registry.register('vpc')
class EKSVpcFilter(VpcFilter):

    RelatedIdsExpression = 'resourcesVpcConfig.vpcId'


@EKS.action_registry.register('tag')
class EKSTag(tags.Tag):

    permissions = ('eks:TagResource',)

    def process_resource_set(self, client, resource_set, tags):
        for r in resource_set:
            try:
                self.manager.retry(
                    client.tag_resource,
                    resourceArn=r['arn'],
                    tags={t['Key']: t['Value'] for t in tags})
            except client.exceptions.ResourceNotFoundException:
                continue


EKS.filter_registry.register('marked-for-op', tags.TagActionFilter)
EKS.action_registry.register('mark-for-op', tags.TagDelayedAction)


@EKS.action_registry.register('remove-tag')
class EKSRemoveTag(tags.RemoveTag):

    permissions = ('eks:UntagResource',)

    def process_resource_set(self, client, resource_set, tags):
        for r in resource_set:
            try:
                self.manager.retry(
                    client.untag_resource,
                    resourceArn=r['arn'], tagKeys=tags)
            except client.exceptions.ResourceNotFoundException:
                continue


@EKS.action_registry.register('update-config')
class UpdateConfig(Action):

    schema = {
        'type': 'object',
        'additionalProperties': False,
        'oneOf': [
            {'required': ['type', 'logging']},
            {'required': ['type', 'resourcesVpcConfig']},
            {'required': ['type', 'logging', 'resourcesVpcConfig']}],
        'properties': {
            'type': {'enum': ['update-config']},
            'logging': {'type': 'object'},
            'resourcesVpcConfig': {'type': 'object'}
        }
    }

    permissions = ('eks:UpdateClusterConfig',)
    shape = 'UpdateClusterConfigRequest'

    def validate(self):
        cfg = dict(self.data)
        cfg['name'] = 'validate'
        cfg.pop('type')
        return shape_validate(
            cfg, self.shape, self.manager.resource_type.service)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('eks')
        state_filtered = 0
        params = dict(self.data)
        params.pop('type')
        for r in resources:
            if r['status'] != 'ACTIVE':
                state_filtered += 1
                continue
            client.update_cluster_config(name=r['name'], **params)
        if state_filtered:
            self.log.warning(
                "Filtered %d of %d clusters due to state", state_filtered, len(resources))


@EKS.action_registry.register('delete')
class Delete(Action):

    schema = type_schema('delete')
    permissions = ('eks:DeleteCluster',)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('eks')
        for r in resources:
            try:
                client.delete_cluster(name=r['name'])
            except client.exceptions.ResourceNotFoundException:
                continue
