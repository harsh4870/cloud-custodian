# Copyright 2016-2017 Capital One Services, LLC
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

import json

from c7n.actions import RemovePolicyBase, Action
from c7n.exceptions import PolicyValidationError
from c7n.filters import CrossAccountAccessFilter, Filter, ValueFilter
from c7n.manager import resources
from c7n.query import QueryResourceManager, TypeInfo
from c7n import tags
from c7n.utils import local_session, type_schema


@resources.register('ecr')
class ECR(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'ecr'
        enum_spec = ('describe_repositories', 'repositories', None)
        name = "repositoryName"
        arn = id = "repositoryArn"
        arn_type = 'repository'
        filter_name = 'repositoryNames'
        filter_type = 'list'

    def augment(self, resources):
        client = local_session(self.session_factory).client('ecr')
        results = []
        for r in resources:
            try:
                r['Tags'] = client.list_tags_for_resource(
                    resourceArn=r['repositoryArn']).get('tags')
                results.append(r)
            except client.exceptions.RepositoryNotFoundException:
                continue

        return results


@ECR.action_registry.register('tag')
class ECRTag(tags.Tag):

    permissions = ('ecr:TagResource',)

    def process_resource_set(self, client, resources, tags):
        for r in resources:
            try:
                client.tag_resource(resourceArn=r['repositoryArn'], tags=tags)
            except client.exceptions.RepositoryNotFoundException:
                pass


@ECR.action_registry.register('set-scanning')
class ECRSetScanning(Action):

    permissions = ('ecr:PutImageScanningConfiguration',)
    schema = type_schema(
        'set-scanning',
        state={'type': 'boolean', 'default': True})

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('ecr')
        s = self.data.get('state', True)
        for r in resources:
            try:
                client.put_image_scanning_configuration(
                    registryId=r['registryId'],
                    repositoryName=r['repositoryName'],
                    imageScanningConfiguration={
                        'scanOnPush': s})
            except client.exceptions.RepositoryNotFoundException:
                continue


@ECR.action_registry.register('set-immutability')
class ECRSetImmutability(Action):

    permissions = ('ecr:PutImageTagMutability',)
    schema = type_schema(
        'set-immutability',
        state={'type': 'boolean', 'default': True})

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('ecr')
        s = 'IMMUTABLE' if self.data.get('state', True) else 'MUTABLE'
        for r in resources:
            try:
                client.put_image_tag_mutability(
                    registryId=r['registryId'],
                    repositoryName=r['repositoryName'],
                    imageTagMutability=s)
            except client.exceptions.RepositoryNotFoundException:
                continue


@ECR.action_registry.register('remove-tag')
class ECRRemoveTags(tags.RemoveTag):

    permissions = ('ecr:UntagResource',)

    def process_resource_set(self, client, resources, tags):
        for r in resources:
            try:
                client.untag_resource(resourceArn=r['repositoryArn'], tagKeys=tags)
            except client.exceptions.RepositoryNotFoundException:
                pass


ECR.filter_registry.register('marked-for-op', tags.TagActionFilter)
ECR.action_registry.register('mark-for-op', tags.TagDelayedAction)


@ECR.filter_registry.register('cross-account')
class ECRCrossAccountAccessFilter(CrossAccountAccessFilter):
    """Filters all EC2 Container Registries (ECR) with cross-account access

    :example:

    .. code-block:: yaml

            policies:
              - name: ecr-cross-account
                resource: ecr
                filters:
                  - type: cross-account
                    whitelist_from:
                      expr: "accounts.*.accountNumber"
                      url: accounts_url
    """
    permissions = ('ecr:GetRepositoryPolicy',)

    def process(self, resources, event=None):

        client = local_session(self.manager.session_factory).client('ecr')

        def _augment(r):
            try:
                r['Policy'] = client.get_repository_policy(
                    repositoryName=r['repositoryName'])['policyText']
            except client.exceptions.RepositoryPolicyNotFoundException:
                return None
            return r

        self.log.debug("fetching policy for %d repos" % len(resources))
        with self.executor_factory(max_workers=2) as w:
            resources = list(filter(None, w.map(_augment, resources)))

        return super(ECRCrossAccountAccessFilter, self).process(resources, event)


LIFECYCLE_RULE_SCHEMA = {
    'type': 'object',
    'additionalProperties': False,
    'required': ['rulePriority', 'action', 'selection'],
    'properties': {
        'rulePriority': {'type': 'integer'},
        'description': {'type': 'string'},
        'action': {
            'type': 'object',
            'required': ['type'],
            'additionalProperties': False,
            'properties': {'type': {'enum': ['expire']}}},
        'selection': {
            'type': 'object',
            'addtionalProperties': False,
            'required': ['countType', 'countUnit'],
            'properties': {
                'tagStatus': {'enum': ['tagged', 'untagged', 'any']},
                'tagPrefixList': {'type': 'array', 'items': {'type': 'string'}},
                'countNumber': {'type': 'integer'},
                'countUnit': {'enum': ['hours', 'days']},
                'countType': {
                    'enum': ['imageCountMoreThan', 'sinceImagePushed']},
            }
        }
    }
}


def lifecycle_rule_validate(policy, rule):
    # This is a non exhaustive list of lifecycle validation rules
    # see this for a more comprehensive list
    #
    # https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html#lp_evaluation_rules

    if (rule['selection']['tagStatus'] == 'tagged' and
            'tagPrefixList' not in rule['selection']):
        raise PolicyValidationError(
            ("{} has invalid lifecycle rule {} tagprefixlist "
             "required for tagStatus: tagged").format(
                 policy.name, rule))
    if (rule['selection']['countType'] == 'sinceImagePushed' and
            'countUnit' not in rule['selection']):
        raise PolicyValidationError(
            ("{} has invalid lifecycle rule {} countUnit "
             "required for countType: sinceImagePushed").format(
                 policy.name, rule))


@ECR.filter_registry.register('lifecycle-rule')
class LifecycleRule(Filter):
    """Lifecycle rule filtering

    :Example:

    .. code-block:: yaml

       policies:
        - name: ecr-life
          resource: aws.ecr
          filters:
            - type: lifecycle-rule
              state: False
              match:
                - selection.tagStatus: untagged
                - action.type: expire
                - type: value
                  key: selection.countNumber
                  value: 30
                  op: less-than
    """
    permissions = ('ecr:GetLifecyclePolicy',)
    schema = type_schema(
        'lifecycle-rule',
        state={'type': 'boolean'},
        match={'type': 'array', 'items': {
            'oneOf': [
                {'$ref': '#/definitions/filters/value'},
                {'type': 'object', 'minProperties': 1, 'maxProperties': 1},
            ]}})
    policy_annotation = 'c7n:lifecycle-policy'

    def process(self, resources, event=None):
        client = local_session(self.manager.session_factory).client('ecr')
        for r in resources:
            if self.policy_annotation in r:
                continue
            try:
                r[self.policy_annotation] = json.loads(
                    client.get_lifecycle_policy(
                        repositoryName=r['repositoryName']).get(
                            'lifecyclePolicyText', ''))
            except client.exceptions.LifecyclePolicyNotFoundException:
                r[self.policy_annotation] = {}

        state = self.data.get('state', False)
        matchers = []
        for matcher in self.data.get('match', []):
            vf = ValueFilter(matcher)
            vf.annotate = False
            matchers.append(vf)

        results = []
        for r in resources:
            found = False
            for rule in r[self.policy_annotation].get('rules', []):
                found = True
                for m in matchers:
                    if not m(rule):
                        found = False
            if found and state:
                results.append(r)
            if not found and not state:
                results.append(r)
        return results


@ECR.action_registry.register('set-lifecycle')
class SetLifecycle(Action):
    """Set the lifecycle policy for ECR repositories.


    Note at the moment this is limited to set/delete/replacement of
    lifecycle policies, not merge.
    """
    permissions = ('ecr:PutLifecyclePolicy', 'ecr:DeleteLifecyclePolicy')

    schema = type_schema(
        'set-lifecycle',
        state={'type': 'boolean'},
        rules={
            'type': 'array',
            'items': LIFECYCLE_RULE_SCHEMA})

    def validate(self):
        if self.data.get('state') is False and 'rules' in self.data:
            raise PolicyValidationError(
                "set-lifecycle can't use statements and state: false")
        elif self.data.get('state', True) and not self.data.get('rules'):
            raise PolicyValidationError(
                "set-lifecycle requires rules with state: true")
        for r in self.data.get('rules', []):
            lifecycle_rule_validate(self.manager.ctx.policy, r)
        return self

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('ecr')
        state = self.data.get('state', True)
        for r in resources:
            if state is False:
                try:
                    client.delete_lifecycle_policy(
                        registryId=r['registryId'],
                        repositoryName=r['repositoryName'])
                    continue
                except client.exceptions.LifecyclePolicyNotFoundException:
                    pass
            client.put_lifecycle_policy(
                registryId=r['registryId'],
                repositoryName=r['repositoryName'],
                lifecyclePolicyText=json.dumps({'rules': self.data['rules']}))


@ECR.action_registry.register('remove-statements')
class RemovePolicyStatement(RemovePolicyBase):
    """Action to remove policy statements from ECR

    :example:

    .. code-block:: yaml

            policies:
              - name: ecr-remove-cross-accounts
                resource: ecr
                filters:
                  - type: cross-account
                actions:
                  - type: remove-statements
                    statement_ids: matched
    """

    permissions = ("ecr:SetRepositoryPolicy", "ecr:GetRepositoryPolicy")

    def process(self, resources):
        results = []
        client = local_session(self.manager.session_factory).client('ecr')
        for r in resources:
            try:
                results += filter(None, [self.process_resource(client, r)])
            except Exception:
                self.log.exception(
                    "Error processing ecr registry:%s", r['repositoryArn'])
        return results

    def process_resource(self, client, resource):
        if 'Policy' not in resource:
            try:
                resource['Policy'] = client.get_repository_policy(
                    repositoryName=resource['repositoryName'])['policyText']
            except client.exceptions.RepositoryPolicyNotFoundException:
                return

        p = json.loads(resource['Policy'])
        statements, found = self.process_policy(
            p, resource, CrossAccountAccessFilter.annotation_key)

        if not found:
            return

        if not statements:
            client.delete_repository_policy(
                repositoryName=resource['repositoryName'])
        else:
            client.set_repository_policy(
                repositoryName=resource['repositoryName'],
                policyText=json.dumps(p))
        return {'Name': resource['repositoryName'],
                'State': 'PolicyRemoved',
                'Statements': found}
