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

from c7n.actions import RemovePolicyBase, ModifyPolicyBase, BaseAction
from c7n.filters import CrossAccountAccessFilter, PolicyChecker
from c7n.filters.kms import KmsRelatedFilter
from c7n.manager import resources
from c7n.query import QueryResourceManager, TypeInfo
from c7n.resolver import ValuesFrom
from c7n.utils import local_session, type_schema
from c7n.tags import RemoveTag, Tag, TagDelayedAction, TagActionFilter


@resources.register('sns')
class SNS(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'sns'
        arn_type = 'topic'
        enum_spec = ('list_topics', 'Topics', None)
        detail_spec = (
            'get_topic_attributes', 'TopicArn', 'TopicArn', 'Attributes')
        id = 'TopicArn'
        name = 'DisplayName'
        dimension = 'TopicName'
        default_report_fields = (
            'TopicArn',
            'DisplayName',
            'SubscriptionsConfirmed',
            'SubscriptionsPending',
            'SubscriptionsDeleted'
        )

    permissions = ('sns:ListTagsForResource',)

    def augment(self, resources):
        client = local_session(self.session_factory).client('sns')

        def _augment(r):
            tags = self.retry(client.list_tags_for_resource,
                ResourceArn=r['TopicArn'])['Tags']
            r['Tags'] = tags
            return r

        resources = super(SNS, self).augment(resources)
        with self.executor_factory(max_workers=3) as w:
            return list(w.map(_augment, resources))


SNS.filter_registry.register('marked-for-op', TagActionFilter)


@SNS.action_registry.register('tag')
class TagTopic(Tag):
    """Action to create tag(s) on sns

    :example:

    .. code-block:: yaml

            policies:
              - name: tag-sns
                resource: sns
                filters:
                  - "tag:target-tag": absent
                actions:
                  - type: tag
                    key: target-tag
                    value: target-tag-value
    """

    permissions = ('sns:TagResource',)

    def process_resource_set(self, client, resources, new_tags):
        for r in resources:
            try:
                client.tag_resource(
                    ResourceArn=r['TopicArn'],
                    Tags=new_tags)
            except client.exceptions.ResourceNotFound:
                continue


@SNS.action_registry.register('remove-tag')
class UntagTopic(RemoveTag):
    """Action to remove tag(s) on sns

    :example:

    .. code-block:: yaml

            policies:
              - name: sns-remove-tag
                resource: sns
                filters:
                  - "tag:OutdatedTag": present
                actions:
                  - type: remove-tag
                    tags: ["OutdatedTag"]
    """

    permissions = ('sns:UntagResource',)

    def process_resource_set(self, client, resources, tags):
        for r in resources:
            try:
                client.untag_resource(ResourceArn=r['TopicArn'], TagKeys=tags)
            except client.exceptions.ResourceNotFound:
                continue


@SNS.action_registry.register('mark-for-op')
class MarkTopicForOp(TagDelayedAction):
    """Mark SNS for deferred action

    :example:

    .. code-block:: yaml

        policies:
          - name: sns-invalid-tag-mark
            resource: sns
            filters:
              - "tag:InvalidTag": present
            actions:
              - type: mark-for-op
                op: delete
                days: 1
    """


class SNSPolicyChecker(PolicyChecker):

    @property
    def allowed_endpoints(self):
        return self.checker_config.get('allowed_endpoints', ())

    @property
    def allowed_protocols(self):
        return self.checker_config.get('allowed_protocols', ())

    def handle_sns_endpoint(self, s, c):
        conditions = self.normalize_conditions(s)
        # yield to aws:sourceowner
        if not self.allowed_endpoints:
            return not any(
                single_condition.get('key', None) == 'aws:sourceowner'
                for single_condition in conditions
            )
        # check if any of the allowed_endpoints are a substring
        # to any of the values in the condition
        for value in c['values']:
            if not any(endpoint in value for endpoint in self.allowed_endpoints):
                return True
        return False

    def handle_sns_protocol(self, s, c):
        return bool(set(c['values']).difference(self.allowed_protocols))


@SNS.filter_registry.register('cross-account')
class SNSCrossAccount(CrossAccountAccessFilter):
    """Filter to return all SNS topics with cross account access permissions

    The whitelist parameter will omit the accounts that match from the return

    :example:

        .. code-block:

            policies:
              - name: sns-cross-account
                resource: sns
                filters:
                  - type: cross-account
                    whitelist:
                      - permitted-account-01
                      - permitted-account-02
    """

    valid_protocols = (
        "http",
        "https",
        "email",
        "email-json",
        "sms",
        "sqs",
        "application",
        "lambda"
    )

    schema = type_schema(
        'cross-account',
        rinherit=CrossAccountAccessFilter.schema,
        whitelist_endpoints={'type': 'array', 'items': {'type': 'string'}},
        whitelist_endpoints_from=ValuesFrom.schema,
        whitelist_protocols={'type': 'array', 'items': {'type': 'string', 'enum': valid_protocols}},
        whitelist_protocols_from=ValuesFrom.schema
    )

    permissions = ('sns:GetTopicAttributes',)

    checker_factory = SNSPolicyChecker

    def process(self, resources, event=None):
        self.endpoints = self.get_endpoints()
        self.protocols = self.get_protocols()
        self.checker_config = getattr(self, 'checker_config', None) or {}
        self.checker_config.update(
            {
                'allowed_endpoints': self.endpoints,
                'allowed_protocols': self.protocols
            }
        )
        return super(SNSCrossAccount, self).process(resources, event)

    def get_endpoints(self):
        endpoints = set(self.data.get('whitelist_endpoints', ()))
        if 'whitelist_endpoints_from' in self.data:
            values = ValuesFrom(self.data['whitelist_endpoints_from'], self.manager)
            endpoints = endpoints.union(values.get_values())
        return endpoints

    def get_protocols(self):
        protocols = set(self.data.get('whitelist_protocols', ()))
        if 'whitelist_protocols_from' in self.data:
            values = ValuesFrom(self.data['whitelist_protocols_from'], self.manager)
            protocols = protocols.union(
                [p for p in values.get_values() if p in self.valid_protocols]
            )
        return protocols


@SNS.action_registry.register('remove-statements')
class RemovePolicyStatement(RemovePolicyBase):
    """Action to remove policy statements from SNS

    :example:

    .. code-block:: yaml

           policies:
              - name: remove-sns-cross-account
                resource: sns
                filters:
                  - type: cross-account
                actions:
                  - type: remove-statements
                    statement_ids: matched
    """

    permissions = ('sns:SetTopicAttributes', 'sns:GetTopicAttributes')

    def process(self, resources):
        results = []
        client = local_session(self.manager.session_factory).client('sns')
        for r in resources:
            try:
                results += filter(None, [self.process_resource(client, r)])
            except Exception:
                self.log.exception(
                    "Error processing sns:%s", r['TopicArn'])
        return results

    def process_resource(self, client, resource):
        p = resource.get('Policy')
        if p is None:
            return

        p = json.loads(resource['Policy'])
        statements, found = self.process_policy(
            p, resource, CrossAccountAccessFilter.annotation_key)

        if not found:
            return

        client.set_topic_attributes(
            TopicArn=resource['TopicArn'],
            AttributeName='Policy',
            AttributeValue=json.dumps(p)
        )
        return {'Name': resource['TopicArn'],
                'State': 'PolicyRemoved',
                'Statements': found}


@SNS.action_registry.register('modify-policy')
class ModifyPolicyStatement(ModifyPolicyBase):

    permissions = ('sns:SetTopicAttributes', 'sns:GetTopicAttributes')

    def process(self, resources):
        results = []
        client = local_session(self.manager.session_factory).client('sns')
        for r in resources:
            policy = json.loads(r.get('Policy') or '{}')
            policy_statements = policy.setdefault('Statement', [])

            new_policy, removed = self.remove_statements(
                policy_statements, r, CrossAccountAccessFilter.annotation_key)
            if new_policy is None:
                new_policy = policy_statements
            new_policy, added = self.add_statements(new_policy)

            if not removed or not added:
                continue

            results += {
                'Name': r['TopicArn'],
                'State': 'PolicyModified',
                'Statements': new_policy
            }
            policy['Statement'] = new_policy
            client.set_topic_attributes(
                TopicArn=r['TopicArn'],
                AttributeName='Policy',
                AttributeValue=json.dumps(policy)
            )
        return results


@SNS.filter_registry.register('kms-key')
class KmsFilter(KmsRelatedFilter):

    RelatedIdsExpression = 'KmsMasterKeyId'


@SNS.action_registry.register('set-encryption')
class SetEncryption(BaseAction):
    """
    Set Encryption on SNS Topics

    By default if no key is specified, alias/aws/sns is used

    key can either be a KMS key ARN, key id, or an alias

    :example:

    .. code-block:: yaml

        policies:
            - name: set-sns-topic-encryption
              resource: sns
              actions:
                - type: set-encryption
                  key: alias/cmk/key
                  enabled: true

            - name: set-sns-topic-encryption-with-id
              resource: sns
              actions:
                - type: set-encryption
                  key: abcdefgh-1234-1234-1234-123456789012
                  enabled: true

            - name: set-sns-topic-encryption-with-arn
              resource: sns
              actions:
                - type: set-encryption
                  key: arn:aws:kms:us-west-1:123456789012:key/abcdefgh-1234-1234-1234-123456789012
                  enabled: true
    """

    schema = type_schema(
        'set-encryption',
        enabled={'type': 'boolean'},
        key={'type': 'string'}
    )

    permissions = ('sns:SetTopicAttributes', 'kms:DescribeKey',)

    def process(self, resources):
        sns = local_session(self.manager.session_factory).client('sns')

        if self.data.get('enabled', True):
            key = self.data.get('key', 'alias/aws/sns')
        else:
            key = ''

        for r in resources:
            sns.set_topic_attributes(
                TopicArn=r['TopicArn'],
                AttributeName='KmsMasterKeyId',
                AttributeValue=key
            )
        return resources


@SNS.action_registry.register('delete')
class DeleteTopic(BaseAction):
    """
    Deletes a SNS Topic

    :example:

    .. code-block:: yaml

      policies:
        - name: delete-bad-topic
          resource: aws.sns
          filters:
            - TopicArn: arn:aws:sns:us-east-2:123456789012:BadTopic
          actions:
            - type: delete
    """

    schema = type_schema('delete')

    permissions = ('sns:DeleteTopic',)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('sns')
        for r in resources:
            try:
                client.delete_topic(TopicArn=r['TopicArn'])
            except client.exceptions.NotFoundException:
                continue
