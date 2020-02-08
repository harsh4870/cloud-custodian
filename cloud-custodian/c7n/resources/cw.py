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

from concurrent.futures import as_completed
from datetime import datetime, timedelta

from c7n.actions import BaseAction
from c7n.exceptions import PolicyValidationError
from c7n.filters import Filter, MetricsFilter
from c7n.filters.iamaccess import CrossAccountAccessFilter
from c7n.query import QueryResourceManager, ChildResourceManager, TypeInfo
from c7n.manager import resources
from c7n.resolver import ValuesFrom
from c7n.tags import universal_augment
from c7n.utils import type_schema, local_session, chunks, get_retry


@resources.register('alarm')
class Alarm(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'cloudwatch'
        arn_type = 'alarm'
        enum_spec = ('describe_alarms', 'MetricAlarms', None)
        id = 'AlarmArn'
        filter_name = 'AlarmNames'
        filter_type = 'list'
        name = 'AlarmName'
        date = 'AlarmConfigurationUpdatedTimestamp'
        config_type = 'AWS::CloudWatch::Alarm'

    retry = staticmethod(get_retry(('Throttled',)))


@Alarm.action_registry.register('delete')
class AlarmDelete(BaseAction):
    """Delete a cloudwatch alarm.

    :example:

    .. code-block:: yaml

            policies:
              - name: cloudwatch-delete-stale-alarms
                resource: alarm
                filters:
                  - type: value
                    value_type: age
                    key: StateUpdatedTimestamp
                    value: 30
                    op: ge
                  - StateValue: INSUFFICIENT_DATA
                actions:
                  - delete
    """

    schema = type_schema('delete')
    permissions = ('cloudwatch:DeleteAlarms',)

    def process(self, resources):
        client = local_session(
            self.manager.session_factory).client('cloudwatch')

        for resource_set in chunks(resources, size=100):
            self.manager.retry(
                client.delete_alarms,
                AlarmNames=[r['AlarmName'] for r in resource_set])


@resources.register('event-rule')
class EventRule(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'events'
        arn_type = 'event-rule'
        enum_spec = ('list_rules', 'Rules', None)
        name = "Name"
        id = "Name"
        filter_name = "NamePrefix"
        filter_type = "scalar"


@EventRule.filter_registry.register('metrics')
class EventRuleMetrics(MetricsFilter):

    def get_dimensions(self, resource):
        return [{'Name': 'RuleName', 'Value': resource['Name']}]


@resources.register('event-rule-target')
class EventRuleTarget(ChildResourceManager):

    class resource_type(TypeInfo):
        service = 'events'
        arn = False
        arn_type = 'event-rule-target'
        enum_spec = ('list_targets_by_rule', 'Targets', None)
        parent_spec = ('event-rule', 'Rule', True)
        name = id = 'Id'


@EventRuleTarget.filter_registry.register('cross-account')
class CrossAccountFilter(CrossAccountAccessFilter):

    schema = type_schema(
        'cross-account',
        # white list accounts
        whitelist_from=ValuesFrom.schema,
        whitelist={'type': 'array', 'items': {'type': 'string'}})

    # dummy permission
    permissions = ('events:ListTargetsByRule',)

    def __call__(self, r):
        account_id = r['Arn'].split(':', 5)[4]
        return account_id not in self.accounts


@EventRuleTarget.action_registry.register('delete')
class DeleteTarget(BaseAction):

    schema = type_schema('delete')
    permissions = ('events:RemoveTargets',)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('events')
        rule_targets = {}
        for r in resources:
            rule_targets.setdefault(r['c7n:parent-id'], []).append(r['Id'])

        for rule_id, target_ids in rule_targets.items():
            client.remove_targets(
                Ids=target_ids,
                Rule=rule_id)


@resources.register('log-group')
class LogGroup(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'logs'
        arn_type = 'log-group'
        enum_spec = ('describe_log_groups', 'logGroups', None)
        name = 'logGroupName'
        id = 'arn'
        filter_name = 'logGroupNamePrefix'
        filter_type = 'scalar'
        dimension = 'LogGroupName'
        date = 'creationTime'
        universal_taggable = True

    def augment(self, resources):
        resources = universal_augment(self, resources)
        for r in resources:
            r['creationTime'] = r['creationTime'] / 1000.0
        return resources

    def get_arns(self, resources):
        # log group arn in resource describe has ':*' suffix, not all
        # apis can use that form, so normalize to standard arn.
        return [r['arn'][:-2] for r in resources]


@LogGroup.action_registry.register('retention')
class Retention(BaseAction):
    """Action to set the retention period (in days) for CloudWatch log groups

    :example:

    .. code-block:: yaml

            policies:
              - name: cloudwatch-set-log-group-retention
                resource: log-group
                actions:
                  - type: retention
                    days: 200
    """

    schema = type_schema('retention', days={'type': 'integer'})
    permissions = ('logs:PutRetentionPolicy',)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('logs')
        days = self.data['days']
        for r in resources:
            client.put_retention_policy(
                logGroupName=r['logGroupName'],
                retentionInDays=days)


@LogGroup.action_registry.register('delete')
class Delete(BaseAction):
    """

    :example:

    .. code-block:: yaml

            policies:
              - name: cloudwatch-delete-stale-log-group
                resource: log-group
                filters:
                  - type: last-write
                    days: 182.5
                actions:
                  - delete
    """

    schema = type_schema('delete')
    permissions = ('logs:DeleteLogGroup',)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('logs')
        for r in resources:
            client.delete_log_group(logGroupName=r['logGroupName'])


@LogGroup.filter_registry.register('last-write')
class LastWriteDays(Filter):
    """Filters CloudWatch log groups by last write

    :example:

    .. code-block:: yaml

            policies:
              - name: cloudwatch-stale-groups
                resource: log-group
                filters:
                  - type: last-write
                    days: 60
    """

    schema = type_schema(
        'last-write', days={'type': 'number'})
    permissions = ('logs:DescribeLogStreams',)

    def process(self, resources, event=None):
        client = local_session(self.manager.session_factory).client('logs')
        self.date_threshold = datetime.utcnow() - timedelta(
            days=self.data['days'])
        return [r for r in resources if self.check_group(client, r)]

    def check_group(self, client, group):
        streams = client.describe_log_streams(
            logGroupName=group['logGroupName'],
            orderBy='LastEventTime',
            descending=True,
            limit=3).get('logStreams')
        group['streams'] = streams
        if not streams:
            last_timestamp = group['creationTime']
        elif streams[0]['storedBytes'] == 0:
            last_timestamp = streams[0]['creationTime']
        else:
            last_timestamp = streams[0]['lastIngestionTime']

        last_write = datetime.fromtimestamp(last_timestamp / 1000.0)
        group['lastWrite'] = last_write
        return self.date_threshold > last_write


@LogGroup.filter_registry.register('cross-account')
class LogCrossAccountFilter(CrossAccountAccessFilter):

    schema = type_schema(
        'cross-account',
        # white list accounts
        whitelist_from=ValuesFrom.schema,
        whitelist={'type': 'array', 'items': {'type': 'string'}})

    permissions = ('logs:DescribeSubscriptionFilters',)

    def process(self, resources, event=None):
        client = local_session(self.manager.session_factory).client('logs')
        accounts = self.get_accounts()
        results = []
        with self.executor_factory(max_workers=1) as w:
            futures = []
            for rset in chunks(resources, 50):
                futures.append(
                    w.submit(
                        self.process_resource_set, client, accounts, rset))
            for f in as_completed(futures):
                if f.exception():
                    self.log.error(
                        "Error checking log groups cross-account %s",
                        f.exception())
                    continue
                results.extend(f.result())
        return results

    def process_resource_set(self, client, accounts, resources):
        results = []
        for r in resources:
            found = False
            filters = self.manager.retry(
                client.describe_subscription_filters,
                logGroupName=r['logGroupName']).get('subscriptionFilters', ())
            for f in filters:
                if 'destinationArn' not in f:
                    continue
                account_id = f['destinationArn'].split(':', 5)[4]
                if account_id not in accounts:
                    r.setdefault('c7n:CrossAccountViolations', []).append(
                        account_id)
                    found = True
            if found:
                results.append(r)
        return results


@LogGroup.action_registry.register('set-encryption')
class EncryptLogGroup(BaseAction):
    """Encrypt/Decrypt a log group

    :example:

    .. code-block:: yaml

        policies:
          - name: encrypt-log-group
            resource: log-group
            filters:
              - kmsKeyId: absent
            actions:
              - type: set-encryption
                kms-key: alias/mylogkey
                state: True

          - name: decrypt-log-group
            resource: log-group
            filters:
              - kmsKeyId: kms:key:arn
            actions:
              - type: set-encryption
                state: False
    """
    schema = type_schema(
        'set-encryption',
        **{'kms-key': {'type': 'string'},
           'state': {'type': 'boolean'}})
    permissions = (
        'logs:AssociateKmsKey', 'logs:DisassociateKmsKey', 'kms:DescribeKey')

    def validate(self):
        if not self.data.get('state', True):
            return self
        key = self.data.get('kms-key', '')
        if not key:
            raise ValueError('Must specify either a KMS key ARN or Alias')
        if 'alias/' not in key and ':key/' not in key:
            raise PolicyValidationError(
                "Invalid kms key format %s" % key)
        return self

    def resolve_key(self, key):
        if not key:
            return

        # Qualified arn for key
        if key.startswith('arn:') and ':key/' in key:
            return key

        # Alias
        key = local_session(
            self.manager.session_factory).client(
                'kms').describe_key(
                    KeyId=key)['KeyMetadata']['Arn']
        return key

    def process(self, resources):
        session = local_session(self.manager.session_factory)
        client = session.client('logs')

        state = self.data.get('state', True)
        key = self.resolve_key(self.data.get('kms-key'))

        for r in resources:
            try:
                if state:
                    client.associate_kms_key(
                        logGroupName=r['logGroupName'], kmsKeyId=key)
                else:
                    client.disassociate_kms_key(logGroupName=r['logGroupName'])
            except client.exceptions.ResourceNotFoundException:
                continue
