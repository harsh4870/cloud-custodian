# Copyright 2018-2019 Amazon.com, Inc. or its affiliates.
# All Rights Reserved.
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

from collections import Counter
from datetime import datetime
from dateutil.tz import tzutc
import jmespath
import json
import hashlib
import logging

from c7n.actions import Action
from c7n.filters import Filter
from c7n.exceptions import PolicyValidationError, PolicyExecutionError
from c7n.policy import LambdaMode, execution
from c7n.utils import (
    local_session, type_schema,
    chunks, dumps, filter_empty, get_partition
)
from c7n.version import version

from .aws import AWS

log = logging.getLogger('c7n.securityhub')


class SecurityHubFindingFilter(Filter):
    """Check if there are Security Hub Findings related to the resources
    """
    schema = type_schema(
        'finding',
        # Many folks do an aggregator region, allow them to use that
        # for filtering.
        region={'type': 'string'},
        query={'type': 'object'})
    schema_alias = True
    permissions = ('securityhub:GetFindings',)
    annotation_key = 'c7n:finding-filter'
    query_shape = 'AwsSecurityFindingFilters'

    def validate(self):
        query = self.data.get('query')
        if query:
            from c7n.resources import aws
            aws.shape_validate(query, self.query_shape, 'securityhub')

    def process(self, resources, event=None):
        client = local_session(
            self.manager.session_factory).client(
                'securityhub', region_name=self.data.get('region'))
        found = []
        params = dict(self.data.get('query', {}))

        for r_arn, resource in zip(self.manager.get_arns(resources), resources):
            params['ResourceId'] = [{"Value": r_arn, "Comparison": "EQUALS"}]
            findings = client.get_findings(Filters=params).get("Findings")
            if len(findings) > 0:
                resource[self.annotation_key] = findings
                found.append(resource)
        return found

    @classmethod
    def register_resources(klass, registry, resource_class):
        """ meta model subscriber on resource registration.

        SecurityHub Findings Filter
        """
        if 'post-finding' not in resource_class.action_registry:
            return
        if not resource_class.has_arn():
            return
        resource_class.filter_registry.register('finding', klass)


@execution.register('hub-action')
@execution.register('hub-finding')
class SecurityHub(LambdaMode):
    """
    Execute a policy lambda in response to security hub finding event or action.

    .. example:

    This policy will provision a lambda and security hub custom action.
    The action can be invoked on a finding or insight result (collection
    of findings). The action name will have the resource type prefixed as
    custodian actions are resource specific.

    .. code-block: yaml

       policy:
         - name: remediate
           resource: aws.ec2
           mode:
             type: hub-action
             role: MyRole
           actions:
            - snapshot
            - type: set-instance-profile
              name: null
            - stop

    .. example:

    This policy will provision a lambda that will process high alert findings from
    guard duty (note custodian also has support for guard duty events directly).

    .. code-block: yaml

       policy:
         - name: remediate
           resource: aws.iam
           filters:
             - type: event
               key: detail.findings[].ProductFields.aws/securityhub/ProductName
               value: GuardDuty
             - type: event
               key: detail.findings[].ProductFields.aws/securityhub/ProductName
               value: GuardDuty
           actions:
             - remove-keys

    Note, for custodian we support additional resources in the finding via the Other resource,
    so these modes work for resources that security hub doesn't natively support.

    https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cloudwatch-events.html
    """

    schema = type_schema(
        'hub-finding', aliases=('hub-action',),
        rinherit=LambdaMode.schema)

    ActionFinding = 'Security Hub Findings - Custom Action'
    ActionInsight = 'Security Hub Insight Results'
    ImportFinding = 'Security Hub Findings - Imported'

    handlers = {
        ActionFinding: 'resolve_action_finding',
        ActionInsight: 'resolve_action_insight',
        ImportFinding: 'resolve_import_finding'
    }

    def resolve_findings(self, findings):
        rids = set()
        for f in findings:
            for r in f['Resources']:
                # Security hub invented some new arn format for a few resources...
                # detect that and normalize to something sane.
                if r['Id'].startswith('AWS') and r['Type'] == 'AwsIamAccessKey':
                    rids.add('arn:aws:iam::%s:user/%s' % (
                        f['AwsAccountId'],
                        r['Details']['AwsIamAccessKey']['UserName']))
                elif not r['Id'].startswith('arn'):
                    log.warning("security hub unknown id:%s rtype:%s",
                                r['Id'], r['Type'])
                else:
                    rids.add(r['Id'])
        return rids

    def resolve_action_insight(self, event):
        rtype = event['detail']['resultType']
        rids = [list(i.keys())[0] for i in event['detail']['insightResults']]
        client = local_session(
            self.policy.session_factory).client('securityhub')
        insights = client.get_insights(
            InsightArns=[event['detail']['insightArn']]).get(
                'Insights', ())
        if not insights or len(insights) > 1:
            return []
        insight = insights.pop()
        params = {}
        params['Filters'] = insight['Filters']
        params['Filters'][rtype] = [
            {'Comparison': 'EQUALS', 'Value': r} for r in rids]
        findings = client.get_findings(**params).get('Findings', ())
        return self.resolve_findings(findings)

    def resolve_action_finding(self, event):
        return self.resolve_findings(event['detail']['findings'])

    def resolve_import_finding(self, event):
        return self.resolve_findings(event['detail']['findings'])

    def run(self, event, lambda_context):
        self.setup_exec_environment(event)
        resource_sets = self.get_resource_sets(event)
        result_sets = {}
        for (account_id, region), rarns in resource_sets.items():
            self.assume_member({'account': account_id, 'region': region})
            resources = self.resolve_resources(event)
            rset = result_sets.setdefault((account_id, region), [])
            if resources:
                rset.extend(self.run_resource_set(event, resources))
        return result_sets

    def get_resource_sets(self, event):
        # return a mapping of (account_id, region): [resource_arns]
        # per the finding in the event.
        resource_arns = self.get_resource_arns(event)
        # Group resources by account_id, region for role assumes
        resource_sets = {}
        for rarn in resource_arns:
            resource_sets.setdefault((rarn.account_id, rarn.region), []).append(rarn)
        # Warn if not configured for member-role and have multiple accounts resources.
        if (not self.policy.data['mode'].get('member-role') and
                set((self.policy.options.account_id,)) != {
                    rarn.account_id for rarn in resource_arns}):
            msg = ('hub-mode not configured for multi-account member-role '
                   'but multiple resource accounts found')
            self.policy.log.warning(msg)
            raise PolicyExecutionError(msg)
        return resource_sets

    def get_resource_arns(self, event):
        event_type = event['detail-type']
        arn_resolver = getattr(self, self.handlers[event_type])
        arns = arn_resolver(event)
        # Lazy import to avoid aws sdk runtime dep in core
        from c7n.resources.aws import Arn
        return {Arn.parse(r) for r in arns}

    def resolve_resources(self, event):
        # For centralized setups in a hub aggregator account
        resource_map = self.get_resource_arns(event)

        # sanity check on finding resources matching policy resource
        # type's service.
        if self.policy.resource_manager.type != 'account':
            log.info(
                "mode:security-hub resolve resources %s", list(resource_map))
            if not resource_map:
                return []
            resource_arns = [
                r for r in resource_map
                if r.service == self.policy.resource_manager.resource_type.service]
            if not resource_arns:
                log.info("mode:security-hub no matching resources arns")
                return []
            resources = self.policy.resource_manager.get_resources(
                [r.resource for r in resource_arns])
        else:
            resources = self.policy.resource_manager.get_resources([])
            resources[0]['resource-arns'] = resource_arns
        return resources


FindingTypes = {
    "Software and Configuration Checks",
    "TTPs",
    "Effects",
    "Unusual Behaviors",
    "Sensitive Data Identifications"
}

# Mostly undocumented value size limit
SECHUB_VALUE_SIZE_LIMIT = 1024


class PostFinding(Action):
    """Report a finding to AWS Security Hub.

    Custodian acts as a finding provider, allowing users to craft
    policies that report to the AWS SecurityHub in the AWS Security Finding Format documented at
    https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html

    For resources that are taggable, we will tag the resource with an identifier
    such that further findings generate updates.

    Example generate a finding for accounts that don't have shield enabled.

    :example:

    .. code-block:: yaml

      policies:

       - name: account-shield-enabled
         resource: account
         filters:
           - shield-enabled
         actions:
           - type: post-finding
             description: |
                Shield should be enabled on account to allow for DDOS protection (1 time 3k USD Charge).
             severity_normalized: 6
             types:
               - "Software and Configuration Checks/Industry and Regulatory Standards/NIST CSF Controls (USA)"
             recommendation: "Enable shield"
             recommendation_url: "https://www.example.com/policies/AntiDDoS.html"
             confidence: 100
             compliance_status: FAILED

    """ # NOQA

    FindingVersion = "2018-10-08"
    ProductName = "default"

    permissions = ('securityhub:BatchImportFindings',)

    schema_alias = True
    schema = type_schema(
        "post-finding",
        required=["types"],
        title={"type": "string", 'default': 'policy.name'},
        description={'type': 'string', 'default':
            'policy.description, or if not defined in policy then policy.name'},
        severity={"type": "number", 'default': 0},
        severity_normalized={"type": "number", "min": 0, "max": 100, 'default': 0},
        confidence={"type": "number", "min": 0, "max": 100},
        criticality={"type": "number", "min": 0, "max": 100},
        # Cross region aggregation
        region={'type': 'string', 'description': 'cross-region aggregation target'},
        recommendation={"type": "string"},
        recommendation_url={"type": "string"},
        fields={"type": "object"},
        batch_size={'type': 'integer', 'minimum': 1, 'maximum': 10, 'default': 1},
        types={
            "type": "array",
            "minItems": 1,
            "items": {"type": "string"},
        },
        compliance_status={
            "type": "string",
            "enum": ["PASSED", "WARNING", "FAILED", "NOT_AVAILABLE"],
        },
        record_state={
            "type": "string", 'default': 'ACTIVE',
            "enum": ["ACTIVE", "ARCHIVED"],
        },
    )

    NEW_FINDING = 'New'

    def validate(self):
        for finding_type in self.data["types"]:
            if finding_type.count('/') > 2 or finding_type.split('/')[0] not in FindingTypes:
                raise PolicyValidationError(
                    "Finding types must be in the format 'namespace/category/classifier'."
                    " Found {}. Valid namespace values are: {}.".format(
                        finding_type, " | ".join([ns for ns in FindingTypes])))

    def get_finding_tag(self, resource):
        finding_tag = None
        tags = resource.get('Tags', [])

        finding_key = '{}:{}'.format('c7n:FindingId',
            self.data.get('title', self.manager.ctx.policy.name))

        # Support Tags as dictionary
        if isinstance(tags, dict):
            return tags.get(finding_key)

        # Support Tags as list of {'Key': 'Value'}
        for t in tags:
            key = t['Key']
            value = t['Value']
            if key == finding_key:
                finding_tag = value
        return finding_tag

    def group_resources(self, resources):
        grouped_resources = {}
        for r in resources:
            finding_tag = self.get_finding_tag(r) or self.NEW_FINDING
            grouped_resources.setdefault(finding_tag, []).append(r)
        return grouped_resources

    def process(self, resources, event=None):
        region_name = self.data.get('region', self.manager.config.region)
        client = local_session(
            self.manager.session_factory).client(
                "securityhub", region_name=region_name)

        now = datetime.utcnow().replace(tzinfo=tzutc()).isoformat()
        # default batch size to one to work around security hub console issue
        # which only shows a single resource in a finding.
        batch_size = self.data.get('batch_size', 1)
        stats = Counter()
        for key, grouped_resources in self.group_resources(resources).items():
            for resource_set in chunks(grouped_resources, batch_size):
                stats['Finding'] += 1
                if key == self.NEW_FINDING:
                    finding_id = None
                    created_at = now
                    updated_at = now
                else:
                    finding_id, created_at = self.get_finding_tag(
                        resource_set[0]).split(':', 1)
                    updated_at = now

                finding = self.get_finding(
                    resource_set, finding_id, created_at, updated_at)
                import_response = client.batch_import_findings(
                    Findings=[finding])
                if import_response['FailedCount'] > 0:
                    stats['Failed'] += import_response['FailedCount']
                    self.log.error(
                        "import_response=%s" % (import_response))
                if key == self.NEW_FINDING:
                    stats['New'] += len(resource_set)
                    # Tag resources with new finding ids
                    tag_action = self.manager.action_registry.get('tag')
                    if tag_action is None:
                        continue
                    tag_action({
                        'key': '{}:{}'.format(
                            'c7n:FindingId',
                            self.data.get(
                                'title', self.manager.ctx.policy.name)),
                        'value': '{}:{}'.format(
                            finding['Id'], created_at)},
                        self.manager).process(resource_set)
                else:
                    stats['Update'] += len(resource_set)

        self.log.debug(
            "policy:%s securityhub %d findings resources %d new %d updated %d failed",
            self.manager.ctx.policy.name,
            stats['Finding'],
            stats['New'],
            stats['Update'],
            stats['Failed'])

    def get_finding(self, resources, existing_finding_id, created_at, updated_at):
        policy = self.manager.ctx.policy
        model = self.manager.resource_type
        region = self.data.get('region', self.manager.config.region)

        if existing_finding_id:
            finding_id = existing_finding_id
        else:
            finding_id = '{}/{}/{}/{}'.format(
                self.manager.config.region,
                self.manager.config.account_id,
                hashlib.md5(json.dumps(
                    policy.data).encode('utf8')).hexdigest(),
                hashlib.md5(json.dumps(list(sorted(
                    [r[model.id] for r in resources]))).encode(
                        'utf8')).hexdigest())
        finding = {
            "SchemaVersion": self.FindingVersion,
            "ProductArn": "arn:aws:securityhub:{}:{}:product/{}/{}".format(
                region,
                self.manager.config.account_id,
                self.manager.config.account_id,
                self.ProductName,
            ),
            "AwsAccountId": self.manager.config.account_id,
            # Long search chain for description values, as this was
            # made required long after users had policies deployed, so
            # use explicit description, or policy description, or
            # explicit title, or policy name, in that order.
            "Description": self.data.get(
                "description", policy.data.get(
                    "description",
                    self.data.get('title', policy.name))).strip(),
            "Title": self.data.get("title", policy.name),
            'Id': finding_id,
            "GeneratorId": policy.name,
            'CreatedAt': created_at,
            'UpdatedAt': updated_at,
            "RecordState": "ACTIVE",
        }

        severity = {'Product': 0, 'Normalized': 0}
        if self.data.get("severity") is not None:
            severity["Product"] = self.data["severity"]
        if self.data.get("severity_normalized") is not None:
            severity["Normalized"] = self.data["severity_normalized"]
        if severity:
            finding["Severity"] = severity

        recommendation = {}
        if self.data.get("recommendation"):
            recommendation["Text"] = self.data["recommendation"]
        if self.data.get("recommendation_url"):
            recommendation["Url"] = self.data["recommendation_url"]
        if recommendation:
            finding["Remediation"] = {"Recommendation": recommendation}

        if "confidence" in self.data:
            finding["Confidence"] = self.data["confidence"]
        if "criticality" in self.data:
            finding["Criticality"] = self.data["criticality"]
        if "compliance_status" in self.data:
            finding["Compliance"] = {"Status": self.data["compliance_status"]}
        if "record_state" in self.data:
            finding["RecordState"] = self.data["record_state"]

        fields = {
            'resource': policy.resource_type,
            'ProviderName': 'CloudCustodian',
            'ProviderVersion': version
        }

        if "fields" in self.data:
            fields.update(self.data["fields"])
        else:
            tags = {}
            for t in policy.tags:
                if ":" in t:
                    k, v = t.split(":", 1)
                else:
                    k, v = t, ""
                tags[k] = v
            fields.update(tags)
        if fields:
            finding["ProductFields"] = fields

        finding_resources = []
        for r in resources:
            finding_resources.append(self.format_resource(r))
        finding["Resources"] = finding_resources
        finding["Types"] = list(self.data["types"])

        return filter_empty(finding)

    def format_resource(self, r):
        raise NotImplementedError("subclass responsibility")


class OtherResourcePostFinding(PostFinding):

    fields = ()

    def format_resource(self, r):
        details = {}
        for k in r:
            if isinstance(k, (list, dict)):
                continue
            details[k] = r[k]

        for f in self.fields:
            value = jmespath.search(f['expr'], r)
            if not value:
                continue
            details[f['key']] = value

        for k, v in details.items():
            if isinstance(v, datetime):
                v = v.isoformat()
            elif isinstance(v, (list, dict)):
                v = dumps(v)
            elif isinstance(v, (int, float, bool)):
                v = str(v)
            else:
                continue
            details[k] = v[:SECHUB_VALUE_SIZE_LIMIT]

        details['c7n:resource-type'] = self.manager.type
        other = {
            'Type': 'Other',
            'Id': self.manager.get_arns([r])[0],
            'Region': self.manager.config.region,
            'Partition': get_partition(self.manager.config.region),
            'Details': {'Other': filter_empty(details)}
        }
        tags = {t['Key']: t['Value'] for t in r.get('Tags', [])}
        if tags:
            other['Tags'] = tags
        return other

    @classmethod
    def register_resource(klass, registry, resource_class):
        if 'post-finding' not in resource_class.action_registry:
            resource_class.action_registry.register('post-finding', klass)


AWS.resources.subscribe(OtherResourcePostFinding.register_resource)
AWS.resources.subscribe(SecurityHubFindingFilter.register_resources)
