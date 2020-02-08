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
"""AWS Account as a custodian resource.
"""
from __future__ import absolute_import, division, print_function, unicode_literals

import json
import time
from botocore.exceptions import ClientError
from datetime import datetime, timedelta

from dateutil.parser import parse as parse_date
from dateutil.tz import tzutc

from c7n.actions import ActionRegistry, BaseAction
from c7n.exceptions import PolicyValidationError
from c7n.filters import Filter, FilterRegistry, ValueFilter
from c7n.filters.kms import KmsRelatedFilter
from c7n.filters.multiattr import MultiAttrFilter
from c7n.filters.missing import Missing
from c7n.manager import ResourceManager, resources
from c7n.utils import local_session, type_schema, generate_arn
from c7n.query import QueryResourceManager, TypeInfo

from c7n.resources.iam import CredentialReport
from c7n.resources.securityhub import OtherResourcePostFinding

filters = FilterRegistry('aws.account.filters')
actions = ActionRegistry('aws.account.actions')

retry = staticmethod(QueryResourceManager.retry)
filters.register('missing', Missing)


def get_account(session_factory, config):
    session = local_session(session_factory)
    client = session.client('iam')
    aliases = client.list_account_aliases().get(
        'AccountAliases', ('',))
    name = aliases and aliases[0] or ""
    return {'account_id': config.account_id,
            'account_name': name}


@resources.register('account')
class Account(ResourceManager):

    filter_registry = filters
    action_registry = actions
    retry = staticmethod(QueryResourceManager.retry)

    class resource_type(TypeInfo):
        id = 'account_id'
        name = 'account_name'
        filter_name = None
        global_resource = True
        # fake this for doc gen
        service = "account"

    @classmethod
    def get_permissions(cls):
        return ('iam:ListAccountAliases',)

    @classmethod
    def has_arn(cls):
        return True

    def get_arns(self, resources):
        return ["arn:::{account_id}".format(**r) for r in resources]

    def get_model(self):
        return self.resource_type

    def resources(self):
        return self.filter_resources([get_account(self.session_factory, self.config)])

    def get_resources(self, resource_ids):
        return [get_account(self.session_factory, self.config)]


@filters.register('credential')
class AccountCredentialReport(CredentialReport):

    def process(self, resources, event=None):
        super(AccountCredentialReport, self).process(resources, event)
        report = self.get_credential_report()
        if report is None:
            return []
        results = []
        info = report.get('<root_account>')
        for r in resources:
            if self.match(r, info):
                r['c7n:credential-report'] = info
                results.append(r)
        return results


@filters.register('check-cloudtrail')
class CloudTrailEnabled(Filter):
    """Verify cloud trail enabled for this account per specifications.

    Returns an annotated account resource if trail is not enabled.

    Of particular note, the current-region option will evaluate whether cloudtrail is available
    in the current region, either as a multi region trail or as a trail with it as the home region.

    :example:

    .. code-block:: yaml

            policies:
              - name: account-cloudtrail-enabled
                resource: account
                region: us-east-1
                filters:
                  - type: check-cloudtrail
                    global-events: true
                    multi-region: true
                    running: true
    """
    schema = type_schema(
        'check-cloudtrail',
        **{'multi-region': {'type': 'boolean'},
           'global-events': {'type': 'boolean'},
           'current-region': {'type': 'boolean'},
           'running': {'type': 'boolean'},
           'notifies': {'type': 'boolean'},
           'file-digest': {'type': 'boolean'},
           'kms': {'type': 'boolean'},
           'kms-key': {'type': 'string'}})

    permissions = ('cloudtrail:DescribeTrails', 'cloudtrail:GetTrailStatus')

    def process(self, resources, event=None):
        session = local_session(self.manager.session_factory)
        client = session.client('cloudtrail')
        trails = client.describe_trails()['trailList']
        resources[0]['c7n:cloudtrails'] = trails
        if self.data.get('global-events'):
            trails = [t for t in trails if t.get('IncludeGlobalServiceEvents')]
        if self.data.get('current-region'):
            current_region = session.region_name
            trails = [t for t in trails if t.get(
                'HomeRegion') == current_region or t.get('IsMultiRegionTrail')]
        if self.data.get('kms'):
            trails = [t for t in trails if t.get('KmsKeyId')]
        if self.data.get('kms-key'):
            trails = [t for t in trails
                      if t.get('KmsKeyId', '') == self.data['kms-key']]
        if self.data.get('file-digest'):
            trails = [t for t in trails
                      if t.get('LogFileValidationEnabled')]
        if self.data.get('multi-region'):
            trails = [t for t in trails if t.get('IsMultiRegionTrail')]
        if self.data.get('notifies'):
            trails = [t for t in trails if t.get('SnsTopicARN')]
        if self.data.get('running', True):
            running = []
            for t in list(trails):
                t['Status'] = status = client.get_trail_status(
                    Name=t['TrailARN'])
                if status['IsLogging'] and not status.get(
                        'LatestDeliveryError'):
                    running.append(t)
            trails = running
        if trails:
            return []
        return resources


@filters.register('guard-duty')
class GuardDutyEnabled(MultiAttrFilter):
    """Check if the guard duty service is enabled.

    This allows looking at account's detector and its associated
    master if any.

    :example:

     Check to ensure guard duty is active on account and associated to a master.

    .. code-block:: yaml

            policies:
              - name: guardduty-enabled
                resource: account
                filters:
                  - type: guard-duty
                    Detector.Status: ENABLED
                    Master.AccountId: "00011001"
                    Master.RelationshipStatus: "Enabled"
    """

    schema = {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'type': {'enum': ['guard-duty']},
            'match-operator': {'enum': ['or', 'and']}},
        'patternProperties': {
            '^Detector': {'oneOf': [{'type': 'object'}, {'type': 'string'}]},
            '^Master': {'oneOf': [{'type': 'object'}, {'type': 'string'}]}},
    }

    annotation = "c7n:guard-duty"
    permissions = (
        'guardduty:GetMasterAccount',
        'guardduty:ListDetectors',
        'guardduty:GetDetector')

    def validate(self):
        attrs = set()
        for k in self.data:
            if k.startswith('Detector') or k.startswith('Master'):
                attrs.add(k)
        self.multi_attrs = attrs
        return super(GuardDutyEnabled, self).validate()

    def get_target(self, resource):
        if self.annotation in resource:
            return resource[self.annotation]

        client = local_session(self.manager.session_factory).client('guardduty')
        # detectors are singletons too.
        detector_ids = client.list_detectors().get('DetectorIds')

        if not detector_ids:
            return None
        else:
            detector_id = detector_ids.pop()

        detector = client.get_detector(DetectorId=detector_id)
        detector.pop('ResponseMetadata', None)
        master = client.get_master_account(DetectorId=detector_id).get('Master')
        resource[self.annotation] = r = {'Detector': detector, 'Master': master}
        return r


@filters.register('check-config')
class ConfigEnabled(Filter):
    """Is config service enabled for this account

    :example:

    .. code-block:: yaml

            policies:
              - name: account-check-config-services
                resource: account
                region: us-east-1
                filters:
                  - type: check-config
                    all-resources: true
                    global-resources: true
                    running: true
    """

    schema = type_schema(
        'check-config', **{
            'all-resources': {'type': 'boolean'},
            'running': {'type': 'boolean'},
            'global-resources': {'type': 'boolean'}})

    permissions = ('config:DescribeDeliveryChannels',
                   'config:DescribeConfigurationRecorders',
                   'config:DescribeConfigurationRecorderStatus')

    def process(self, resources, event=None):
        client = local_session(
            self.manager.session_factory).client('config')
        channels = client.describe_delivery_channels()[
            'DeliveryChannels']
        recorders = client.describe_configuration_recorders()[
            'ConfigurationRecorders']
        resources[0]['c7n:config_recorders'] = recorders
        resources[0]['c7n:config_channels'] = channels
        if self.data.get('global-resources'):
            recorders = [
                r for r in recorders
                if r['recordingGroup'].get('includeGlobalResourceTypes')]
        if self.data.get('all-resources'):
            recorders = [r for r in recorders
                         if r['recordingGroup'].get('allSupported')]
        if self.data.get('running', True) and recorders:
            status = {s['name']: s for
                      s in client.describe_configuration_recorder_status(
            )['ConfigurationRecordersStatus']}
            resources[0]['c7n:config_status'] = status
            recorders = [r for r in recorders if status[r['name']]['recording'] and
                status[r['name']]['lastStatus'].lower() in ('pending', 'success')]
        if channels and recorders:
            return []
        return resources


@filters.register('iam-summary')
class IAMSummary(ValueFilter):
    """Return annotated account resource if iam summary filter matches.

    Some use cases include, detecting root api keys or mfa usage.

    Example iam summary wrt to matchable fields::

      {
            "AccessKeysPerUserQuota": 2,
            "AccountAccessKeysPresent": 0,
            "AccountMFAEnabled": 1,
            "AccountSigningCertificatesPresent": 0,
            "AssumeRolePolicySizeQuota": 2048,
            "AttachedPoliciesPerGroupQuota": 10,
            "AttachedPoliciesPerRoleQuota": 10,
            "AttachedPoliciesPerUserQuota": 10,
            "GroupPolicySizeQuota": 5120,
            "Groups": 1,
            "GroupsPerUserQuota": 10,
            "GroupsQuota": 100,
            "InstanceProfiles": 0,
            "InstanceProfilesQuota": 100,
            "MFADevices": 3,
            "MFADevicesInUse": 2,
            "Policies": 3,
            "PoliciesQuota": 1000,
            "PolicySizeQuota": 5120,
            "PolicyVersionsInUse": 5,
            "PolicyVersionsInUseQuota": 10000,
            "Providers": 0,
            "RolePolicySizeQuota": 10240,
            "Roles": 4,
            "RolesQuota": 250,
            "ServerCertificates": 0,
            "ServerCertificatesQuota": 20,
            "SigningCertificatesPerUserQuota": 2,
            "UserPolicySizeQuota": 2048,
            "Users": 5,
            "UsersQuota": 5000,
            "VersionsPerPolicyQuota": 5,
        }

    For example to determine if an account has either not been
    enabled with root mfa or has root api keys.

    .. code-block:: yaml

      policies:
        - name: root-keys-or-no-mfa
          resource: account
          filters:
            - type: iam-summary
              key: AccountMFAEnabled
              value: true
              op: eq
              value_type: swap
    """
    schema = type_schema('iam-summary', rinherit=ValueFilter.schema)
    schema_alias = False
    permissions = ('iam:GetAccountSummary',)

    def process(self, resources, event=None):
        if not resources[0].get('c7n:iam_summary'):
            client = local_session(
                self.manager.session_factory).client('iam')
            resources[0]['c7n:iam_summary'] = client.get_account_summary(
            )['SummaryMap']
        if self.match(resources[0]['c7n:iam_summary']):
            return resources
        return []


@filters.register('password-policy')
class AccountPasswordPolicy(ValueFilter):
    """Check an account's password policy.

    Note that on top of the default password policy fields, we also add an extra key,
    PasswordPolicyConfigured which will be set to true or false to signify if the given
    account has attempted to set a policy at all.

    :example:

    .. code-block:: yaml

            policies:
              - name: password-policy-check
                resource: account
                region: us-east-1
                filters:
                  - type: password-policy
                    key: MinimumPasswordLength
                    value: 10
                    op: ge
                  - type: password-policy
                    key: RequireSymbols
                    value: true
    """
    schema = type_schema('password-policy', rinherit=ValueFilter.schema)
    schema_alias = False
    permissions = ('iam:GetAccountPasswordPolicy',)

    def process(self, resources, event=None):
        account = resources[0]
        if not account.get('c7n:password_policy'):
            client = local_session(self.manager.session_factory).client('iam')
            policy = {}
            try:
                policy = client.get_account_password_policy().get('PasswordPolicy', {})
                policy['PasswordPolicyConfigured'] = True
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    policy['PasswordPolicyConfigured'] = False
                else:
                    raise
            account['c7n:password_policy'] = policy
        if self.match(account['c7n:password_policy']):
            return resources
        return []


@filters.register('service-limit')
class ServiceLimit(Filter):
    """Check if account's service limits are past a given threshold.

    Supported limits are per trusted advisor, which is variable based
    on usage in the account and support level enabled on the account.

      - service: AutoScaling limit: Auto Scaling groups
      - service: AutoScaling limit: Launch configurations
      - service: EBS limit: Active snapshots
      - service: EBS limit: Active volumes
      - service: EBS limit: General Purpose (SSD) volume storage (GiB)
      - service: EBS limit: Magnetic volume storage (GiB)
      - service: EBS limit: Provisioned IOPS
      - service: EBS limit: Provisioned IOPS (SSD) storage (GiB)
      - service: EC2 limit: Elastic IP addresses (EIPs)

      # Note this is extant for each active instance type in the account
      # however the total value is against sum of all instance types.
      # see issue https://github.com/cloud-custodian/cloud-custodian/issues/516

      - service: EC2 limit: On-Demand instances - m3.medium

      - service: EC2 limit: Reserved Instances - purchase limit (monthly)
      - service: ELB limit: Active load balancers
      - service: IAM limit: Groups
      - service: IAM limit: Instance profiles
      - service: IAM limit: Roles
      - service: IAM limit: Server certificates
      - service: IAM limit: Users
      - service: RDS limit: DB instances
      - service: RDS limit: DB parameter groups
      - service: RDS limit: DB security groups
      - service: RDS limit: DB snapshots per user
      - service: RDS limit: Storage quota (GB)
      - service: RDS limit: Internet gateways
      - service: SES limit: Daily sending quota
      - service: VPC limit: VPCs
      - service: VPC limit: VPC Elastic IP addresses (EIPs)

    :example:

    .. code-block:: yaml

            policies:
              - name: increase-account-service-limits
                resource: account
                filters:
                  - type: service-limit
                    services:
                      - EC2
                    threshold: 1.0
              - name: specify-region-for-global-service
                region: us-east-1
                resource: account
                filters:
                  - type: service-limit
                    services:
                      - IAM
                    limits:
                      - Roles
    """

    schema = type_schema(
        'service-limit',
        threshold={'type': 'number'},
        refresh_period={'type': 'integer',
                        'title': 'how long should a check result be considered fresh'},
        limits={'type': 'array', 'items': {'type': 'string'}},
        services={'type': 'array', 'items': {
            'enum': ['EC2', 'ELB', 'VPC', 'AutoScaling',
                     'RDS', 'EBS', 'SES', 'IAM']}})

    permissions = ('support:DescribeTrustedAdvisorCheckResult',)
    check_id = 'eW7HH0l7J9'
    check_limit = ('region', 'service', 'check', 'limit', 'extant', 'color')

    # When doing a refresh, how long to wait for the check to become ready.
    # Max wait here is 5 * 10 ~ 50 seconds.
    poll_interval = 5
    poll_max_intervals = 10
    global_services = set(['IAM'])

    def validate(self):
        region = self.manager.data.get('region', '')
        if len(self.global_services.intersection(self.data.get('services', []))):
            if region != 'us-east-1':
                raise PolicyValidationError(
                    "Global services: %s must be targeted in us-east-1 on the policy"
                    % ', '.join(self.global_services))
        return self

    @classmethod
    def get_check_result(cls, client, check_id):
        checks = client.describe_trusted_advisor_check_result(
            checkId=check_id, language='en')['result']

        # Check status and if necessary refresh checks
        if checks['status'] == 'not_available':
            client.refresh_trusted_advisor_check(checkId=check_id)
            for _ in range(cls.poll_max_intervals):
                time.sleep(cls.poll_interval)
                refresh_response = client.describe_trusted_advisor_check_refresh_statuses(
                    checkIds=[check_id])
                if refresh_response['statuses'][0]['status'] == 'success':
                    checks = client.describe_trusted_advisor_check_result(
                        checkId=check_id, language='en')['result']
                    break
        return checks

    def process(self, resources, event=None):
        client = local_session(self.manager.session_factory).client(
            'support', region_name='us-east-1')
        checks = self.get_check_result(client, self.check_id)

        region = self.manager.config.region
        checks['flaggedResources'] = [r for r in checks['flaggedResources']
            if r['metadata'][0] == region or (r['metadata'][0] == '-' and region == 'us-east-1')]
        resources[0]['c7n:ServiceLimits'] = checks

        delta = timedelta(self.data.get('refresh_period', 1))
        check_date = parse_date(checks['timestamp'])
        if datetime.now(tz=tzutc()) - delta > check_date:
            client.refresh_trusted_advisor_check(checkId=self.check_id)
        threshold = self.data.get('threshold')

        services = self.data.get('services')
        limits = self.data.get('limits')
        exceeded = []

        for resource in checks['flaggedResources']:
            if threshold is None and resource['status'] == 'ok':
                continue
            limit = dict(zip(self.check_limit, resource['metadata']))
            if services and limit['service'] not in services:
                continue
            if limits and limit['check'] not in limits:
                continue
            limit['status'] = resource['status']
            limit['percentage'] = float(limit['extant'] or 0) / float(
                limit['limit']) * 100
            if threshold and limit['percentage'] < threshold:
                continue
            exceeded.append(limit)
        if exceeded:
            resources[0]['c7n:ServiceLimitsExceeded'] = exceeded
            return resources
        return []


@actions.register('request-limit-increase')
class RequestLimitIncrease(BaseAction):
    r"""File support ticket to raise limit.

    :Example:

    .. code-block:: yaml

        policies:
          - name: raise-account-service-limits
            resource: account
            filters:
              - type: service-limit
                services:
                  - EBS
                limits:
                  - Provisioned IOPS (SSD) storage (GiB)
                threshold: 60.5
            actions:
              - type: request-limit-increase
                notify: [email, email2]
                ## You can use one of either percent-increase or an amount-increase.
                percent-increase: 50
                message: "Please raise the below account limit(s); \n {limits}"
    """

    schema = {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'type': {'enum': ['request-limit-increase']},
            'percent-increase': {'type': 'number', 'minimum': 1},
            'amount-increase': {'type': 'number', 'minimum': 1},
            'minimum-increase': {'type': 'number', 'minimum': 1},
            'subject': {'type': 'string'},
            'message': {'type': 'string'},
            'notify': {'type': 'array', 'items': {'type': 'string'}},
            'severity': {'type': 'string', 'enum': ['urgent', 'high', 'normal', 'low']}
        },
        'oneOf': [
            {'required': ['type', 'percent-increase']},
            {'required': ['type', 'amount-increase']}
        ]
    }

    permissions = ('support:CreateCase',)

    default_subject = '[Account:{account}]Raise the following limit(s) of {service} in {region}'
    default_template = 'Please raise the below account limit(s); \n {limits}'
    default_severity = 'normal'

    service_code_mapping = {
        'AutoScaling': 'auto-scaling',
        'ELB': 'elastic-load-balancing',
        'EBS': 'amazon-elastic-block-store',
        'EC2': 'amazon-elastic-compute-cloud-linux',
        'RDS': 'amazon-relational-database-service-aurora',
        'VPC': 'amazon-virtual-private-cloud',
        'IAM': 'aws-identity-and-access-management',
        'CloudFormation': 'aws-cloudformation',
        'Kinesis': 'amazon-kinesis',
    }

    def process(self, resources):
        session = local_session(self.manager.session_factory)
        client = session.client('support', region_name='us-east-1')
        account_id = self.manager.config.account_id
        service_map = {}
        region_map = {}
        limit_exceeded = resources[0].get('c7n:ServiceLimitsExceeded', [])
        percent_increase = self.data.get('percent-increase')
        amount_increase = self.data.get('amount-increase')
        minimum_increase = self.data.get('minimum-increase', 1)

        for s in limit_exceeded:
            current_limit = int(s['limit'])
            if percent_increase:
                increase_by = current_limit * float(percent_increase) / 100
                increase_by = max(increase_by, minimum_increase)
            else:
                increase_by = amount_increase
            increase_by = round(increase_by)
            msg = '\nIncrease %s by %d in %s \n\t Current Limit: %s\n\t Current Usage: %s\n\t ' \
                  'Set New Limit to: %d' % (
                      s['check'], increase_by, s['region'], s['limit'], s['extant'],
                      (current_limit + increase_by))
            service_map.setdefault(s['service'], []).append(msg)
            region_map.setdefault(s['service'], s['region'])

        for service in service_map:
            subject = self.data.get('subject', self.default_subject).format(
                service=service, region=region_map[service], account=account_id)
            service_code = self.service_code_mapping.get(service)
            body = self.data.get('message', self.default_template)
            body = body.format(**{
                'service': service,
                'limits': '\n\t'.join(service_map[service]),
            })
            client.create_case(
                subject=subject,
                communicationBody=body,
                serviceCode=service_code,
                categoryCode='general-guidance',
                severityCode=self.data.get('severity', self.default_severity),
                ccEmailAddresses=self.data.get('notify', []))


def cloudtrail_policy(original, bucket_name, account_id, bucket_region):
    '''add CloudTrail permissions to an S3 policy, preserving existing'''
    ct_actions = [
        {
            'Action': 's3:GetBucketAcl',
            'Effect': 'Allow',
            'Principal': {'Service': 'cloudtrail.amazonaws.com'},
            'Resource': generate_arn(
                service='s3', resource=bucket_name, region=bucket_region),
            'Sid': 'AWSCloudTrailAclCheck20150319',
        },
        {
            'Action': 's3:PutObject',
            'Condition': {
                'StringEquals':
                {'s3:x-amz-acl': 'bucket-owner-full-control'},
            },
            'Effect': 'Allow',
            'Principal': {'Service': 'cloudtrail.amazonaws.com'},
            'Resource': generate_arn(
                service='s3', resource=bucket_name, region=bucket_region),
            'Sid': 'AWSCloudTrailWrite20150319',
        },
    ]
    # parse original policy
    if original is None:
        policy = {
            'Statement': [],
            'Version': '2012-10-17',
        }
    else:
        policy = json.loads(original['Policy'])
    original_actions = [a.get('Action') for a in policy['Statement']]
    for cta in ct_actions:
        if cta['Action'] not in original_actions:
            policy['Statement'].append(cta)
    return json.dumps(policy)


# AWS Account doesn't participate in events (not based on query resource manager)
# so the event subscriber used by postfinding to register doesn't apply, manually
# register it.
Account.action_registry.register('post-finding', OtherResourcePostFinding)


@actions.register('enable-cloudtrail')
class EnableTrail(BaseAction):
    """Enables logging on the trail(s) named in the policy

    :Example:

    .. code-block:: yaml

        policies:
          - name: trail-test
            description: Ensure CloudTrail logging is enabled
            resource: account
            actions:
              - type: enable-cloudtrail
                trail: mytrail
                bucket: trails
    """

    permissions = (
        'cloudtrail:CreateTrail',
        'cloudtrail:DescribeTrails',
        'cloudtrail:GetTrailStatus',
        'cloudtrail:StartLogging',
        'cloudtrail:UpdateTrail',
        's3:CreateBucket',
        's3:GetBucketPolicy',
        's3:PutBucketPolicy',
    )
    schema = type_schema(
        'enable-cloudtrail',
        **{
            'trail': {'type': 'string'},
            'bucket': {'type': 'string'},
            'bucket-region': {'type': 'string'},
            'multi-region': {'type': 'boolean'},
            'global-events': {'type': 'boolean'},
            'notify': {'type': 'string'},
            'file-digest': {'type': 'boolean'},
            'kms': {'type': 'boolean'},
            'kms-key': {'type': 'string'},
            'required': ('bucket',),
        }
    )

    def process(self, accounts):
        """Create or enable CloudTrail"""
        session = local_session(self.manager.session_factory)
        client = session.client('cloudtrail')
        bucket_name = self.data['bucket']
        bucket_region = self.data.get('bucket-region', 'us-east-1')
        trail_name = self.data.get('trail', 'default-trail')
        multi_region = self.data.get('multi-region', True)
        global_events = self.data.get('global-events', True)
        notify = self.data.get('notify', '')
        file_digest = self.data.get('file-digest', False)
        kms = self.data.get('kms', False)
        kms_key = self.data.get('kms-key', '')

        s3client = session.client('s3', region_name=bucket_region)
        try:
            s3client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': bucket_region}
            )
        except ClientError as ce:
            if not ('Error' in ce.response and
            ce.response['Error']['Code'] == 'BucketAlreadyOwnedByYou'):
                raise ce

        try:
            current_policy = s3client.get_bucket_policy(Bucket=bucket_name)
        except ClientError:
            current_policy = None

        policy_json = cloudtrail_policy(
            current_policy, bucket_name,
            self.manager.config.account_id, bucket_region)

        s3client.put_bucket_policy(Bucket=bucket_name, Policy=policy_json)
        trails = client.describe_trails().get('trailList', ())
        if trail_name not in [t.get('Name') for t in trails]:
            new_trail = client.create_trail(
                Name=trail_name,
                S3BucketName=bucket_name,
            )
            if new_trail:
                trails.append(new_trail)
                # the loop below will configure the new trail
        for trail in trails:
            if trail.get('Name') != trail_name:
                continue
            # enable
            arn = trail['TrailARN']
            status = client.get_trail_status(Name=arn)
            if not status['IsLogging']:
                client.start_logging(Name=arn)
            # apply configuration changes (if any)
            update_args = {}
            if multi_region != trail.get('IsMultiRegionTrail'):
                update_args['IsMultiRegionTrail'] = multi_region
            if global_events != trail.get('IncludeGlobalServiceEvents'):
                update_args['IncludeGlobalServiceEvents'] = global_events
            if notify != trail.get('SNSTopicArn'):
                update_args['SnsTopicName'] = notify
            if file_digest != trail.get('LogFileValidationEnabled'):
                update_args['EnableLogFileValidation'] = file_digest
            if kms_key != trail.get('KmsKeyId'):
                if not kms and 'KmsKeyId' in trail:
                    kms_key = ''
                update_args['KmsKeyId'] = kms_key
            if update_args:
                update_args['Name'] = trail_name
                client.update_trail(**update_args)


@filters.register('has-virtual-mfa')
class HasVirtualMFA(Filter):
    """Is the account configured with a virtual MFA device?

    :example:

    .. code-block:: yaml

            policies:
                - name: account-with-virtual-mfa
                  resource: account
                  region: us-east-1
                  filters:
                    - type: has-virtual-mfa
                      value: true
    """

    schema = type_schema('has-virtual-mfa', **{'value': {'type': 'boolean'}})

    permissions = ('iam:ListVirtualMFADevices',)

    def mfa_belongs_to_root_account(self, mfa):
        return mfa['SerialNumber'].endswith(':mfa/root-account-mfa-device')

    def account_has_virtual_mfa(self, account):
        if not account.get('c7n:VirtualMFADevices'):
            client = local_session(self.manager.session_factory).client('iam')
            paginator = client.get_paginator('list_virtual_mfa_devices')
            raw_list = paginator.paginate().build_full_result()['VirtualMFADevices']
            account['c7n:VirtualMFADevices'] = list(filter(
                self.mfa_belongs_to_root_account, raw_list))
        expect_virtual_mfa = self.data.get('value', True)
        has_virtual_mfa = any(account['c7n:VirtualMFADevices'])
        return expect_virtual_mfa == has_virtual_mfa

    def process(self, resources, event=None):
        return list(filter(self.account_has_virtual_mfa, resources))


@actions.register('enable-data-events')
class EnableDataEvents(BaseAction):
    """Ensure all buckets in account are setup to log data events.

    Note this works via a single trail for data events per
    https://aws.amazon.com/about-aws/whats-new/2017/09/aws-cloudtrail-enables-option-to-add-all-amazon-s3-buckets-to-data-events/

    This trail should NOT be used for api management events, the
    configuration here is soley for data events. If directed to create
    a trail this will do so without management events.

    :example:

    .. code-block:: yaml

            policies:
              - name: s3-enable-data-events-logging
                resource: account
                actions:
                 - type: enable-data-events
                   data-trail:
                     name: s3-events
                     multi-region: us-east-1
    """

    schema = type_schema(
        'enable-data-events', required=['data-trail'], **{
            'data-trail': {
                'type': 'object',
                'additionalProperties': False,
                'required': ['name'],
                'properties': {
                    'create': {
                        'title': 'Should we create trail if needed for events?',
                        'type': 'boolean'},
                    'type': {'enum': ['ReadOnly', 'WriteOnly', 'All']},
                    'name': {
                        'title': 'The name of the event trail',
                        'type': 'string'},
                    'topic': {
                        'title': 'If creating, the sns topic for the trail to send updates',
                        'type': 'string'},
                    's3-bucket': {
                        'title': 'If creating, the bucket to store trail event data',
                        'type': 'string'},
                    's3-prefix': {'type': 'string'},
                    'key-id': {
                        'title': 'If creating, Enable kms on the trail',
                        'type': 'string'},
                    # region that we're aggregating via trails.
                    'multi-region': {
                        'title': 'If creating, use this region for all data trails',
                        'type': 'string'}}}})

    def validate(self):
        if self.data['data-trail'].get('create'):
            if 's3-bucket' not in self.data['data-trail']:
                raise PolicyValidationError(
                    "If creating data trails, an s3-bucket is required on %s" % (
                        self.manager.data))
        return self

    def get_permissions(self):
        perms = [
            'cloudtrail:DescribeTrails',
            'cloudtrail:GetEventSelectors',
            'cloudtrail:PutEventSelectors']

        if self.data.get('data-trail', {}).get('create'):
            perms.extend([
                'cloudtrail:CreateTrail', 'cloudtrail:StartLogging'])
        return perms

    def add_data_trail(self, client, trail_cfg):
        if not trail_cfg.get('create'):
            raise ValueError(
                "s3 data event trail missing and not configured to create")
        params = dict(
            Name=trail_cfg['name'],
            S3BucketName=trail_cfg['s3-bucket'],
            EnableLogFileValidation=True)

        if 'key-id' in trail_cfg:
            params['KmsKeyId'] = trail_cfg['key-id']
        if 's3-prefix' in trail_cfg:
            params['S3KeyPrefix'] = trail_cfg['s3-prefix']
        if 'topic' in trail_cfg:
            params['SnsTopicName'] = trail_cfg['topic']
        if 'multi-region' in trail_cfg:
            params['IsMultiRegionTrail'] = True

        client.create_trail(**params)
        return {'Name': trail_cfg['name']}

    def process(self, resources):
        session = local_session(self.manager.session_factory)
        region = self.data['data-trail'].get('multi-region')

        if region:
            client = session.client('cloudtrail', region_name=region)
        else:
            client = session.client('cloudtrail')

        added = False
        tconfig = self.data['data-trail']
        trails = client.describe_trails(
            trailNameList=[tconfig['name']]).get('trailList', ())
        if not trails:
            trail = self.add_data_trail(client, tconfig)
            added = True
        else:
            trail = trails[0]

        events = client.get_event_selectors(
            TrailName=trail['Name']).get('EventSelectors', [])

        for e in events:
            found = False
            if not e.get('DataResources'):
                continue
            for data_events in e['DataResources']:
                if data_events['Type'] != 'AWS::S3::Object':
                    continue
                for b in data_events['Values']:
                    if b.rsplit(':')[-1].strip('/') == '':
                        found = True
                        break
            if found:
                resources[0]['c7n_data_trail'] = trail
                return

        # Opinionated choice, separate api and data events.
        event_count = len(events)
        events = [e for e in events if not e.get('IncludeManagementEvents')]
        if len(events) != event_count:
            self.log.warning("removing api trail from data trail")

        # future proof'd for other data events, for s3 this trail
        # encompasses all the buckets in the account.

        events.append({
            'IncludeManagementEvents': False,
            'ReadWriteType': tconfig.get('type', 'All'),
            'DataResources': [{
                'Type': 'AWS::S3::Object',
                'Values': ['arn:aws:s3:::']}]})
        client.put_event_selectors(
            TrailName=trail['Name'],
            EventSelectors=events)

        if added:
            client.start_logging(Name=tconfig['name'])

        resources[0]['c7n_data_trail'] = trail


@filters.register('shield-enabled')
class ShieldEnabled(Filter):

    permissions = ('shield:DescribeSubscription',)

    schema = type_schema(
        'shield-enabled',
        state={'type': 'boolean'})

    def process(self, resources, event=None):
        state = self.data.get('state', False)
        client = local_session(self.manager.session_factory).client('shield')
        try:
            subscription = client.describe_subscription().get(
                'Subscription', None)
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                raise
            subscription = None

        resources[0]['c7n:ShieldSubscription'] = subscription
        if state and subscription:
            return resources
        elif not state and not subscription:
            return resources
        return []


@actions.register('set-shield-advanced')
class SetShieldAdvanced(BaseAction):
    """Enable/disable Shield Advanced on an account."""

    permissions = (
        'shield:CreateSubscription', 'shield:DeleteSubscription')

    schema = type_schema(
        'set-shield-advanced',
        state={'type': 'boolean'})

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('shield')
        state = self.data.get('state', True)

        if state:
            client.create_subscription()
        else:
            try:
                client.delete_subscription()
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    return
                raise


@filters.register('xray-encrypt-key')
class XrayEncrypted(Filter):
    """Determine if xray is encrypted.

    :example:

    .. code-block:: yaml

            policies:
              - name: xray-encrypt-with-default
                resource: aws.account
                filters:
                   - type: xray-encrypt-key
                     key: default
              - name: xray-encrypt-with-kms
                resource: aws.account
                filters:
                   - type: xray-encrypt-key
                     key: kms
              - name: xray-encrypt-with-specific-key
                resource: aws.account
                filters:
                   - type: xray-encrypt-key
                     key: alias/my-alias or arn or keyid
    """

    permissions = ('xray:GetEncryptionConfig',)
    schema = type_schema(
        'xray-encrypt-key',
        required=['key'],
        key={'type': 'string'}
    )

    def process(self, resources, event=None):
        client = self.manager.session_factory().client('xray')
        gec_result = client.get_encryption_config()['EncryptionConfig']
        resources[0]['c7n:XrayEncryptionConfig'] = gec_result

        k = self.data.get('key')
        if k not in ['default', 'kms']:
            kmsclient = self.manager.session_factory().client('kms')
            keyid = kmsclient.describe_key(KeyId=k)['KeyMetadata']['Arn']
            rc = resources if (gec_result['KeyId'] == keyid) else []
        else:
            kv = 'KMS' if self.data.get('key') == 'kms' else 'NONE'
            rc = resources if (gec_result['Type'] == kv) else []
        return rc


@actions.register('set-xray-encrypt')
class SetXrayEncryption(BaseAction):
    """Enable specific xray encryption.

    :example:

    .. code-block:: yaml

            policies:
              - name: xray-default-encrypt
                resource: aws.account
                actions:
                  - type: set-xray-encrypt
                    key: default
              - name: xray-kms-encrypt
                resource: aws.account
                actions:
                  - type: set-xray-encrypt
                    key: alias/some/alias/key
    """

    permissions = ('xray:PutEncryptionConfig',)
    schema = type_schema(
        'set-xray-encrypt',
        required=['key'],
        key={'type': 'string'}
    )

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('xray')
        key = self.data.get('key')
        req = {'Type': 'NONE'} if key == 'default' else {'Type': 'KMS', 'KeyId': key}
        client.put_encryption_config(**req)


@filters.register('default-ebs-encryption')
class EbsEncryption(Filter):
    """Filter an account by its ebs encryption status.

    By default for key we match on the alias name for a key.

    :example:

    .. code-block:: yaml

       policies:
         - name: check-default-ebs-encryption
           resource: aws.account
           filters:
            - type: default-ebs-encryption
              key: "alias/aws/ebs"
              state: true

    It is also possible to match on specific key attributes (tags, origin)

    :example:

    .. code-block:: yaml

       policies:
         - name: check-ebs-encryption-key-origin
           resource: aws.account
           filters:
            - type: default-ebs-encryption
              key:
                type: value
                key: Origin
                value: AWS_KMS
              state: true
    """
    permissions = ('ec2:GetEbsEncryptionByDefault',)
    schema = type_schema(
        'default-ebs-encryption',
        state={'type': 'boolean'},
        key={'oneOf': [
            {'$ref': '#/definitions/filters/value'},
            {'type': 'string'}]})

    def process(self, resources, event=None):
        state = self.data.get('state', False)
        client = local_session(self.manager.session_factory).client('ec2')
        account_state = client.get_ebs_encryption_by_default().get(
            'EbsEncryptionByDefault')
        if account_state != state:
            return []
        if state and 'key' in self.data:
            vfd = (isinstance(self.data['key'], dict) and
                   self.data['key'] or {'c7n:AliasName': self.data['key']})
            vf = KmsRelatedFilter(vfd, self.manager)
            vf.RelatedIdsExpression = 'KmsKeyId'
            vf.annotate = False
            key = client.get_ebs_default_kms_key_id().get('KmsKeyId')
            if not vf.process([{'KmsKeyId': key}]):
                return []
        return resources


@actions.register('set-ebs-encryption')
class SetEbsEncryption(BaseAction):
    """Set AWS EBS default encryption on an account

    :example:

    .. code-block:: yaml

       policies:
         - name: set-default-ebs-encryption
           resource: aws.account
           filters:
            - type: default-ebs-encryption
              state: false
           actions:
            - type: set-ebs-encryption
              state: true
              key: alias/aws/ebs
    """
    permissions = ('ec2:EnableEbsEncryptionByDefault',
                   'ec2:DisableEbsEncryptionByDefault')

    schema = type_schema(
        'set-ebs-encryption',
        state={'type': 'boolean'},
        key={'type': 'string'})

    def process(self, resources):
        client = local_session(
            self.manager.session_factory).client('ec2')
        state = self.data.get('state')
        key = self.data.get('key')
        if state:
            client.enable_ebs_encryption_by_default()
        else:
            client.disable_ebs_encryption_by_default()

        if state and key:
            client.modify_ebs_default_kms_key_id(
                KmsKeyId=self.data['key'])


@filters.register('s3-public-block')
class S3PublicBlock(ValueFilter):
    """Check for s3 public blocks on an account.

    https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html
    """

    annotation_key = 'c7n:s3-public-block'
    annotate = False  # no annotation from value filter
    schema = type_schema('s3-public-block', rinherit=ValueFilter.schema)
    schema_alias = False
    permissions = ('s3:GetAccountPublicAccessBlock',)

    def process(self, resources, event=None):
        self.augment([r for r in resources if self.annotation_key not in r])
        return super(S3PublicBlock, self).process(resources, event)

    def augment(self, resources):
        client = local_session(self.manager.session_factory).client('s3control')
        for r in resources:
            try:
                r[self.annotation_key] = client.get_public_access_block(
                    AccountId=r['account_id']).get('PublicAccessBlockConfiguration', {})
            except client.exceptions.NoSuchPublicAccessBlockConfiguration:
                r[self.annotation_key] = {}

    def __call__(self, r):
        return super(S3PublicBlock, self).__call__(r[self.annotation_key])


@actions.register('set-s3-public-block')
class SetS3PublicBlock(BaseAction):
    """Configure S3 Public Access Block on an account.

    All public access block attributes can be set. If not specified they are merged
    with the extant configuration.

    https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html

    :example:

    .. yaml:

      policies:
        - name: restrict-public-buckets
          resource: aws.account
          filters:
            - not:
               - type: s3-public-block
                 key: RestrictPublicBuckets
                 value: true
          actions:
            - type: set-s3-public-block
              RestrictPublicBuckets: true

    """
    schema = type_schema(
        'set-s3-public-block',
        state={'type': 'boolean', 'default': True},
        BlockPublicAcls={'type': 'boolean'},
        IgnorePublicAcls={'type': 'boolean'},
        BlockPublicPolicy={'type': 'boolean'},
        RestrictPublicBuckets={'type': 'boolean'})

    permissions = ('s3:PutAccountPublicAccessBlock', 's3:GetAccountPublicAccessBlock')

    def validate(self):
        config = self.data.copy()
        config.pop('type')
        if config.pop('state', None) is False and config:
            raise PolicyValidationError(
                "%s cant set state false with controls specified".format(
                    self.type))

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('s3control')
        if self.data.get('state', True) is False:
            for r in resources:
                client.delete_public_access_block(AccountId=r['account_id'])
            return

        keys = (
            'BlockPublicPolicy', 'BlockPublicAcls', 'IgnorePublicAcls', 'RestrictPublicBuckets')

        for r in resources:
            # try to merge with existing configuration if not explicitly set.
            base = {}
            if S3PublicBlock.annotation_key in r:
                base = r[S3PublicBlock.annotation_key]
            else:
                try:
                    base = client.get_public_access_block(AccountId=r['account_id']).get(
                        'PublicAccessBlockConfiguration')
                except client.exceptions.NoSuchPublicAccessBlockConfiguration:
                    base = {}

            config = {}
            for k in keys:
                if k in self.data:
                    config[k] = self.data[k]
                elif k in base:
                    config[k] = base[k]

            client.put_public_access_block(
                AccountId=r['account_id'],
                PublicAccessBlockConfiguration=config)


@filters.register('glue-security-config')
class GlueEncryptionEnabled(MultiAttrFilter):
    """Filter aws account by its glue encryption status and KMS key """

    """:example:

    .. yaml:

      policies:
        - name: glue-security-config
          resource: aws.account
          filters:
            - type: glue-security-config
                key: SseAwsKmsKeyId
                value: alias/aws/glue

    """
    retry = staticmethod(QueryResourceManager.retry)

    schema = {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'type': {'enum': ['glue-security-config']},
            'CatalogEncryptionMode': {'type': 'string'},
            'SseAwsKmsKeyId': {'type': 'string'},
            'ReturnConnectionPasswordEncrypted': {'type': 'boolean'},
            'AwsKmsKeyId': {'type': 'string'}
        }
    }

    annotation = "c7n:glue-security-config"
    permissions = ('glue:GetDataCatalogEncryptionSettings',)

    def validate(self):
        attrs = set()
        for key in self.data:
            if key in ['CatalogEncryptionMode',
                       'ReturnConnectionPasswordEncrypted',
                       'SseAwsKmsKeyId',
                       'AwsKmsKeyId']:
                attrs.add(key)
        self.multi_attrs = attrs
        return super(GlueEncryptionEnabled, self).validate()

    def get_target(self, resource):
        if self.annotation in resource:
            return resource[self.annotation]
        client = local_session(self.manager.session_factory).client('glue')
        encryption_setting = client.get_data_catalog_encryption_settings().get(
            'DataCatalogEncryptionSettings')
        resource[self.annotation] = encryption_setting.get('EncryptionAtRest')
        resource[self.annotation].update(encryption_setting.get('ConnectionPasswordEncryption'))

        for kmskey in self.data:
            if not self.data[kmskey].startswith('alias'):
                continue
            key = resource[self.annotation].get(kmskey)
            vfd = {'c7n:AliasName': self.data[kmskey]}
            vf = KmsRelatedFilter(vfd, self.manager)
            vf.RelatedIdsExpression = 'KmsKeyId'
            vf.annotate = False
            if not vf.process([{'KmsKeyId': key}]):
                return []
            resource[self.annotation][kmskey] = self.data[kmskey]
        return resource[self.annotation]
