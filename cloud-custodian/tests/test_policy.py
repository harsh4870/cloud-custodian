# Copyright 2015-2017 Capital One Services, LLC
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

from datetime import datetime, timedelta
import json
import logging
import mock
import shutil
import tempfile

from c7n import policy, manager
from c7n.config import Config
from c7n.provider import clouds
from c7n.exceptions import ResourceLimitExceeded, PolicyValidationError
from c7n.resources import aws, load_resources
from c7n.resources.aws import AWS
from c7n.resources.ec2 import EC2
from c7n.schema import generate, JsonSchemaValidator
from c7n.utils import dumps
from c7n.query import ConfigSource, TypeInfo
from c7n.version import version

from .common import BaseTest, event_data, Bag


class DummyResource(manager.ResourceManager):

    def resources(self):
        return [{"abc": 123}, {"def": 456}]

    @property
    def actions(self):

        class _a(object):

            def name(self):
                return self.f.__name__

            def __init__(self, f):
                self.f = f

            def process(self, resources):
                return self.f(resources)

        def p1(resources):
            return [{"abc": 456}, {"def": 321}]

        def p2(resources):
            return resources

        return [_a(p1), _a(p2)]


class PolicyMetaLint(BaseTest):

    def setUp(self):
        # we need to load all resources for the linting meta tests.
        load_resources()

    def test_policy_missing_provider_session(self):
        self.assertRaises(
            RuntimeError,
            policy.get_session_factory,
            'nosuchthing', Bag())

    def test_policy_detail_spec_permissions(self):
        policy = self.load_policy(
            {"name": "kinesis-delete", "resource": "kinesis", "actions": ["delete"]}
        )
        perms = policy.get_permissions()
        self.assertEqual(
            perms,
            set(
                (
                    "kinesis:DescribeStream",
                    "kinesis:ListStreams",
                    "kinesis:DeleteStream",
                )
            ),
        )

    def test_schema_plugin_name_mismatch(self):
        # todo iterate over all clouds not just aws resources
        for k, v in manager.resources.items():
            for fname, f in v.filter_registry.items():
                if fname in ("or", "and", "not"):
                    continue
                self.assertIn(fname, f.schema["properties"]["type"]["enum"])
            for aname, a in v.action_registry.items():
                self.assertIn(aname, a.schema["properties"]["type"]["enum"])

    def test_schema(self):
        try:
            schema = generate()
            JsonSchemaValidator.check_schema(schema)
        except Exception:
            self.fail("Invalid schema")

    def test_schema_serialization(self):
        try:
            dumps(generate())
        except Exception:
            self.fail("Failed to serialize schema")

    def test_resource_augment_universal_mask(self):
        # universal tag had a potential bad patterm of masking
        # resource augmentation, scan resources to ensure
        missing = []
        for k, v in manager.resources.items():
            if not getattr(v.resource_type, "universal_taggable", None):
                continue
            if (
                v.augment.__name__ == "universal_augment" and
                getattr(v.resource_type, "detail_spec", None)
            ):
                missing.append(k)

        if missing:
            self.fail(
                "%s resource has universal augment masking resource augment" % (
                    ', '.join(missing))
            )

    def test_resource_universal_taggable_arn_type(self):
        missing = []
        for k, v in manager.resources.items():
            if not getattr(v, 'augment', None):
                continue
            if (
                v.augment.__name__ == "universal_augment" and
                    v.resource_type.arn_type is None
            ):
                missing.append(k)

        if missing:
            self.fail("%s universal taggable resource missing arn_type" % (
                ', '.join(missing)))

    def test_resource_shadow_source_augment(self):
        shadowed = []
        bad = []
        cfg = Config.empty()

        for k, v in manager.resources.items():
            if not getattr(v.resource_type, "config_type", None):
                continue

            p = Bag({"name": "permcheck", "resource": k, 'provider_name': 'aws'})
            ctx = self.get_context(config=cfg, policy=p)
            mgr = v(ctx, p)

            source = mgr.get_source("config")
            if not isinstance(source, ConfigSource):
                bad.append(k)

            if v.__dict__.get("augment"):
                shadowed.append(k)

        if shadowed:
            self.fail(
                "%s have resource managers shadowing source augments"
                % (", ".join(shadowed))
            )

        if bad:
            self.fail("%s have config types but no config source" % (", ".join(bad)))

    def test_resource_arn_override_generator(self):
        overrides = set()
        for k, v in manager.resources.items():
            arn_gen = bool(v.__dict__.get('get_arns') or v.__dict__.get('generate_arn'))

            if arn_gen:
                overrides.add(k)

        overrides = overrides.difference(set(
            ('account', 's3', 'hostedzone', 'log-group', 'rest-api', 'redshift-snapshot',
             'rest-stage')))
        if overrides:
            raise ValueError("unknown arn overrides in %s" % (", ".join(overrides)))

    def test_resource_name(self):
        names = []
        for k, v in manager.resources.items():
            if not getattr(v.resource_type, "name", None):
                names.append(k)
        if names:
            self.fail("%s dont have resource name for reporting" % (", ".join(names)))

    def test_resource_meta_with_class(self):
        missing = set()
        for k, v in manager.resources.items():
            if k in ('rest-account', 'account'):
                continue
            if not issubclass(v.resource_type, TypeInfo):
                missing.add(k)
        if missing:
            raise SyntaxError("missing type info class %s" % (', '.join(missing)))

    def test_resource_type_empty_metadata(self):
        empty = set()
        for k, v in manager.resources.items():
            if k in ('rest-account', 'account'):
                continue
            for rk, rv in v.resource_type.__dict__.items():
                if rk[0].isalnum() and rv is None:
                    empty.add(k)
        if empty:
            raise ValueError("Empty Resource Metadata %s" % (', '.join(empty)))

    def test_resource_legacy_type(self):
        legacy = set()
        marker = object()
        for k, v in manager.resources.items():
            if getattr(v.resource_type, 'type', marker) is not marker:
                legacy.add(k)
        if legacy:
            raise SyntaxError("legacy arn type info %s" % (', '.join(legacy)))

    def _visit_filters_and_actions(self, visitor):
        names = []
        for cloud_name, cloud in clouds.items():
            for resource_name, resource in cloud.resources.items():
                for fname, f in resource.filter_registry.items():
                    if fname in ('and', 'or', 'not'):
                        continue
                    if visitor(f):
                        names.append("%s.%s.filters.%s" % (
                            cloud_name, resource_name, fname))
                for aname, a in resource.action_registry.items():
                    if visitor(a):
                        names.append('%s.%s.actions.%s' % (
                            cloud_name, resource_name, aname))
        return names

    def test_filter_action_additional(self):

        def visitor(e):
            if e.type == 'notify':
                return
            return e.schema.get('additionalProperties', True) is True

        names = self._visit_filters_and_actions(visitor)
        if names:
            self.fail(
                "missing additionalProperties: False on actions/filters\n %s" % (
                    " \n".join(names)))

    def test_filter_action_type(self):
        def visitor(e):
            return 'type' not in e.schema['properties']

        names = self._visit_filters_and_actions(visitor)
        if names:
            self.fail("missing type on actions/filters\n %s" % (" \n".join(names)))

    def test_resource_arn_info(self):
        missing = []
        whitelist_missing = set((
            'rest-stage', 'rest-resource', 'rest-vpclink'))
        explicit = []
        whitelist_explicit = set((
            'rest-account', 'shield-protection', 'shield-attack',
            'dlm-policy', 'efs', 'efs-mount-target', 'gamelift-build',
            'glue-connection', 'glue-dev-endpoint', 'cloudhsm-cluster',
            'snowball-cluster', 'snowball', 'ssm-activation',
            'healthcheck', 'event-rule-target',
            'support-case', 'transit-attachment', 'config-recorder'))

        missing_method = []
        for k, v in manager.resources.items():
            rtype = getattr(v, 'resource_type', None)
            if not v.has_arn():
                missing_method.append(k)
            if rtype is None:
                continue
            if v.__dict__.get('get_arns'):
                continue
            if getattr(rtype, 'arn', None) is False:
                explicit.append(k)
            if getattr(rtype, 'arn', None) is not None:
                continue
            if getattr(rtype, 'type', None) is not None:
                continue
            if getattr(rtype, 'arn_type', None) is not None:
                continue
            missing.append(k)

        self.assertEqual(
            set(missing).union(explicit),
            set(missing_method))

        missing = set(missing).difference(whitelist_missing)
        if missing:
            self.fail(
                "%d resources %s are missing arn type info" % (
                    len(missing), ", ".join(missing)))
        explicit = set(explicit).difference(whitelist_explicit)
        if explicit:
            self.fail(
                "%d resources %s dont have arn type info exempted" % (
                    len(explicit), ", ".join(explicit)))

    def test_resource_permissions(self):
        self.capture_logging("c7n.cache")
        missing = []
        cfg = Config.empty()

        for k, v in list(manager.resources.items()):
            p = Bag({"name": "permcheck", "resource": k, 'provider_name': 'aws'})
            ctx = self.get_context(config=cfg, policy=p)

            mgr = v(ctx, p)
            perms = mgr.get_permissions()
            if not perms:
                missing.append(k)

            for n, a in list(v.action_registry.items()):
                p["actions"] = [n]
                perms = a({}, mgr).get_permissions()
                found = bool(perms)
                if not isinstance(perms, (list, tuple, set)):
                    found = False
                if "webhook" == n:
                    continue
                if not found:
                    missing.append("%s.actions.%s" % (k, n))

            for n, f in list(v.filter_registry.items()):
                if n in ("and", "or", "not", "missing"):
                    continue
                p["filters"] = [n]
                perms = f({}, mgr).get_permissions()
                if not isinstance(perms, (tuple, list, set)):
                    missing.append("%s.filters.%s" % (k, n))

                # in memory filters
                if n in (
                    "event",
                    "value",
                    "tag-count",
                    "marked-for-op",
                    "offhour",
                    "onhour",
                    "age",
                    "state-age",
                    "egress",
                    "ingress",
                    "capacity-delta",
                    "is-ssl",
                    "global-grants",
                    "missing-policy-statement",
                    "missing-statement",
                    "healthcheck-protocol-mismatch",
                    "image-age",
                    "has-statement",
                    "no-access",
                    "instance-age",
                    "ephemeral",
                    "instance-uptime",
                ):
                    continue
                qk = "%s.filters.%s" % (k, n)
                if qk in ("route-table.filters.route",):
                    continue
                if not perms:
                    missing.append(qk)

        if missing:
            self.fail(
                "Missing permissions %d on \n\t%s"
                % (len(missing), "\n\t".join(sorted(missing)))
            )


class PolicyMeta(BaseTest):

    def test_policy_detail_spec_permissions(self):
        policy = self.load_policy(
            {"name": "kinesis-delete",
             "resource": "kinesis",
             "actions": ["delete"]}
        )
        perms = policy.get_permissions()
        self.assertEqual(
            perms,
            set(
                (
                    "kinesis:DescribeStream",
                    "kinesis:ListStreams",
                    "kinesis:DeleteStream",
                )
            ),
        )

    def test_policy_manager_custom_permissions(self):
        policy = self.load_policy(
            {
                "name": "ec2-utilization",
                "resource": "ec2",
                "filters": [
                    {
                        "type": "metrics",
                        "name": "CPUUtilization",
                        "days": 3,
                        "value": 1.5,
                    }
                ],
            }
        )
        perms = policy.get_permissions()
        self.assertEqual(
            perms,
            set(
                (
                    "ec2:DescribeInstances",
                    "ec2:DescribeTags",
                    "cloudwatch:GetMetricStatistics",
                )
            ),
        )


class TestPolicyCollection(BaseTest):

    def test_expand_partitions(self):
        cfg = Config.empty(regions=["us-gov-west-1", "cn-north-1", "us-west-2"])
        original = policy.PolicyCollection.from_data(
            {"policies": [{"name": "foo", "resource": "ec2"}]}, cfg
        )

        collection = AWS().initialize_policies(original, cfg)
        self.assertEqual(
            sorted([p.options.region for p in collection]),
            ["cn-north-1", "us-gov-west-1", "us-west-2"],
        )

    def test_policy_expand_group_region(self):
        cfg = Config.empty(regions=["us-east-1", "us-east-2", "us-west-2"])
        original = policy.PolicyCollection.from_data(
            {"policies": [
                {"name": "bar", "resource": "lambda"},
                {"name": "middle", "resource": "security-group"},
                {"name": "foo", "resource": "ec2"}]},
            cfg)

        collection = AWS().initialize_policies(original, cfg)
        self.assertEqual(
            [(p.name, p.options.region) for p in collection],
            [('bar', 'us-east-1'),
             ('middle', 'us-east-1'),
             ('foo', 'us-east-1'),
             ('bar', 'us-east-2'),
             ('middle', 'us-east-2'),
             ('foo', 'us-east-2'),
             ('bar', 'us-west-2'),
             ('middle', 'us-west-2'),
             ('foo', 'us-west-2')])

    def test_policy_region_expand_global(self):
        factory = self.replay_flight_data('test_aws_policy_global_expand')
        self.patch(aws, '_profile_session', factory())
        original = self.policy_loader.load_data(
            {"policies": [
                {"name": "foo", "resource": "s3"},
                {"name": "iam", "resource": "iam-user"}]},
            'memory://',
            config=Config.empty(regions=["us-east-1", "us-west-2"]),
        )

        collection = AWS().initialize_policies(original, Config.empty(regions=["all"]))
        self.assertEqual(len(collection.resource_types), 2)
        s3_regions = [p.options.region for p in collection if p.resource_type == "s3"]
        self.assertTrue("us-east-1" in s3_regions)
        self.assertTrue("us-east-2" in s3_regions)
        iam = [p for p in collection if p.resource_type == "iam-user"]
        self.assertEqual(len(iam), 1)
        self.assertEqual(iam[0].options.region, "us-east-1")

        collection = AWS().initialize_policies(
            original, Config.empty(regions=["eu-west-1", "eu-west-2"])
        )
        iam = [p for p in collection if p.resource_type == "iam-user"]
        self.assertEqual(len(iam), 1)
        self.assertEqual(iam[0].options.region, "eu-west-1")
        self.assertEqual(len(collection), 3)


class TestPolicy(BaseTest):

    def test_policy_variable_precedent(self):
        p = self.load_policy({
            'name': 'compute',
            'resource': 'aws.ec2'},
            config={'account_id': '00100100'})

        v = p.get_variables({'account_id': 'foobar',
                             'charge_code': 'oink'})
        self.assertEqual(v['account_id'], '00100100')
        self.assertEqual(v['charge_code'], 'oink')

    def test_policy_with_role_complete(self):
        p = self.load_policy({
            'name': 'compute',
            'resource': 'aws.ec2',
            'mode': {
                'type': 'config-rule',
                'member-role': 'arn:aws:iam::{account_id}:role/BarFoo',
                'role': 'arn:aws:iam::{account_id}:role/FooBar'},
            'actions': [
                {'type': 'tag',
                 'value': 'bad monkey {account_id} {region} {now:+2d%Y-%m-%d}'},
                {'type': 'notify',
                 'to': ['me@example.com'],
                 'transport': {
                     'type': 'sns',
                     'topic': 'arn:::::',
                 },
                 'subject': "S3 - Cross-Account -[custodian {{ account }} - {{ region }}]"},
            ]}, config={'account_id': '12312311', 'region': 'zanzibar'})

        p.expand_variables(p.get_variables())
        self.assertEqual(p.data['mode']['role'], 'arn:aws:iam::12312311:role/FooBar')

    def test_policy_variable_interpolation(self):

        p = self.load_policy({
            'name': 'compute',
            'resource': 'aws.ec2',
            'mode': {
                'type': 'config-rule',
                'member-role': 'arn:aws:iam::{account_id}:role/BarFoo',
                'role': 'FooBar'},
            'actions': [
                {'type': 'tag',
                 'value': 'bad monkey {account_id} {region} {now:+2d%Y-%m-%d}'},
                {'type': 'notify',
                 'to': ['me@example.com'],
                 'transport': {
                     'type': 'sns',
                     'topic': 'arn:::::',
                 },
                 'subject': "S3 - Cross-Account -[custodian {{ account }} - {{ region }}]"},
            ]}, config={'account_id': '12312311', 'region': 'zanzibar'})

        ivalue = 'bad monkey 12312311 zanzibar %s' % (
            (datetime.utcnow() + timedelta(2)).strftime('%Y-%m-%d'))
        p.expand_variables(p.get_variables())
        self.assertEqual(p.data['actions'][0]['value'], ivalue)
        self.assertEqual(
            p.data['actions'][1]['subject'],
            "S3 - Cross-Account -[custodian {{ account }} - {{ region }}]")
        self.assertEqual(p.data['mode']['role'], 'arn:aws:iam::12312311:role/FooBar')
        self.assertEqual(p.data['mode']['member-role'], 'arn:aws:iam::{account_id}:role/BarFoo')
        self.assertEqual(p.resource_manager.actions[0].data['value'], ivalue)

    def test_child_resource_trail_validation(self):
        self.assertRaises(
            ValueError,
            self.load_policy,
            {
                "name": "api-resources",
                "resource": "rest-resource",
                "mode": {
                    "type": "cloudtrail",
                    "events": [
                        {
                            "source": "apigateway.amazonaws.com",
                            "event": "UpdateResource",
                            "ids": "requestParameter.stageName",
                        }
                    ],
                },
            },
        )

    def test_load_policy_validation_error(self):
        invalid_policies = {
            "policies": [
                {
                    "name": "foo",
                    "resource": "s3",
                    "filters": [{"tag:custodian_tagging": "not-null"}],
                    "actions": [
                        {"type": "untag", "tags": {"custodian_cleanup": "yes"}}
                    ],
                }
            ]
        }
        self.assertRaises(Exception, self.load_policy_set, invalid_policies)

    def test_policy_validation(self):
        policy = self.load_policy(
            {
                "name": "ec2-utilization",
                "resource": "ec2",
                "tags": ["abc"],
                "filters": [
                    {
                        "type": "metrics",
                        "name": "CPUUtilization",
                        "days": 3,
                        "value": 1.5,
                    }
                ],
                "actions": ["stop"],
            }
        )
        policy.validate()
        self.assertEqual(policy.tags, ["abc"])
        self.assertFalse(policy.is_lambda)
        self.assertTrue(
            repr(policy).startswith("<Policy resource:ec2 name:ec2-utilization")
        )

    def test_policy_name_and_resource_type_filtering(self):

        collection = self.load_policy_set(
            {
                "policies": [
                    {"name": "s3-remediate", "resource": "s3"},
                    {"name": "s3-global-grants", "resource": "s3"},
                    {"name": "ec2-tag-compliance-stop", "resource": "ec2"},
                    {"name": "ec2-tag-compliance-kill", "resource": "ec2"},
                    {"name": "ec2-tag-compliance-remove", "resource": "ec2"},
                ]
            }
        )

        self.assertIn("s3-remediate", collection)
        self.assertNotIn("s3-argle-bargle", collection)

        # Make sure __iter__ works
        for p in collection:
            self.assertTrue(p.name is not None)

        self.assertEqual(collection.resource_types, set(("s3", "ec2")))
        self.assertTrue("s3-remediate" in collection)

        self.assertEqual(
            [p.name for p in collection.filter(["s3*"])],
            ["s3-remediate", "s3-global-grants"],
        )

        self.assertEqual(
            [p.name for p in collection.filter(["ec2*"])],
            [
                "ec2-tag-compliance-stop",
                "ec2-tag-compliance-kill",
                "ec2-tag-compliance-remove",
            ],
        )

        self.assertEqual(
            [p.name for p in collection.filter(["ec2*", "s3*"])],
            [p.name for p in collection],
        )

        self.assertEqual(
            [p.name for p in collection.filter(resource_types=["ec2"])],
            [
                "ec2-tag-compliance-stop",
                "ec2-tag-compliance-kill",
                "ec2-tag-compliance-remove",
            ],
        )

        self.assertEqual(
            [p.name for p in collection.filter(resource_types=["ec2", "s3"])],
            [p.name for p in collection],
        )

        self.assertEqual(
            [p.name for p in collection.filter(["ec2*", "s3*"], ["ec2", "s3"])],
            [p.name for p in collection],
        )

        self.assertEqual(
            [p.name for p in collection.filter(["ec2*", "s3*"], ["s3"])],
            [
                "s3-remediate",
                "s3-global-grants",
            ],
        )

        self.assertEqual(
            [p.name for p in collection.filter(["asdf12"])],
            [],
        )

        self.assertEqual(
            [p.name for p in collection.filter(resource_types=["asdf12"])],
            [],
        )

    def test_file_not_found(self):
        self.assertRaises(IOError, policy.load, Config.empty(), "/asdf12")

    def test_lambda_policy_metrics(self):
        session_factory = self.replay_flight_data("test_lambda_policy_metrics")
        p = self.load_policy(
            {
                "name": "ec2-tag-compliance-v6",
                "resource": "ec2",
                "mode": {"type": "ec2-instance-state", "events": ["running"]},
                "filters": [
                    {"tag:custodian_status": "absent"},
                    {
                        "or": [
                            {"tag:App": "absent"},
                            {"tag:Env": "absent"},
                            {"tag:Owner": "absent"},
                        ]
                    },
                ],
            },
            session_factory=session_factory,
        )
        end = datetime.utcnow()
        start = end - timedelta(14)
        period = 24 * 60 * 60 * 14
        self.assertEqual(
            json.loads(dumps(p.get_metrics(start, end, period), indent=2)),
            {
                u"Durations": [],
                u"Errors": [
                    {
                        u"Sum": 0.0,
                        u"Timestamp": u"2016-05-30T10:50:00+00:00",
                        u"Unit": u"Count",
                    }
                ],
                u"Invocations": [
                    {
                        u"Sum": 4.0,
                        u"Timestamp": u"2016-05-30T10:50:00+00:00",
                        u"Unit": u"Count",
                    }
                ],
                u"ResourceCount": [
                    {
                        u"Average": 1.0,
                        u"Sum": 2.0,
                        u"Timestamp": u"2016-05-30T10:50:00+00:00",
                        u"Unit": u"Count",
                    }
                ],
                u"Throttles": [
                    {
                        u"Sum": 0.0,
                        u"Timestamp": u"2016-05-30T10:50:00+00:00",
                        u"Unit": u"Count",
                    }
                ],
            },
        )

    def test_policy_resource_limits(self):
        session_factory = self.replay_flight_data(
            "test_policy_resource_limits")
        p = self.load_policy(
            {
                "name": "log-delete",
                "resource": "log-group",
                "max-resources-percent": 2.5,
            },
            session_factory=session_factory)
        p.ctx.metrics.flush = mock.MagicMock()
        output = self.capture_logging('custodian.policy', level=logging.ERROR)
        self.assertRaises(ResourceLimitExceeded, p.run)
        self.assertEqual(
            output.getvalue().strip(),
            "policy:log-delete exceeded resource-limit:2.5% found:1 total:1")
        self.assertEqual(
            p.ctx.metrics.buf[0]['MetricName'], 'ResourceLimitExceeded')

    def test_policy_resource_limits_count(self):
        session_factory = self.replay_flight_data(
            "test_policy_resource_count")
        p = self.load_policy(
            {
                "name": "ecs-cluster-resource-count",
                "resource": "ecs",
                "max-resources": 1
            },
            session_factory=session_factory)
        self.assertRaises(ResourceLimitExceeded, p.run)
        policy = {
            "name": "ecs-cluster-resource-count",
            "resource": "ecs",
            "max-resources": 0
        }
        config = Config.empty(validate=True)
        self.assertRaises(
            Exception,
            self.load_policy,
            policy,
            config=config,
            validate=True,
            session_factory=session_factory
        )

    def test_policy_resource_limit_and_percent(self):
        session_factory = self.replay_flight_data(
            "test_policy_resource_count")
        p = self.load_policy(
            {
                "name": "ecs-cluster-resource-count",
                "resource": "ecs",
                "max-resources": {
                    "amount": 1,
                    "percent": 10,
                    "op": "and"
                }
            },
            session_factory=session_factory)
        self.assertRaises(ResourceLimitExceeded, p.run)
        p = self.load_policy(
            {
                "name": "ecs-cluster-resource-count",
                "resource": "ecs",
                "max-resources": {
                    "amount": 100,
                    "percent": 10,
                    "op": "and"
                }
            },
            session_factory=session_factory)
        resources = p.run()
        self.assertTrue(resources)

    def test_policy_resource_limits_with_filter(self):
        session_factory = self.replay_flight_data(
            "test_policy_resource_count_with_filter")
        p = self.load_policy(
            {
                "name": "asg-with-image-age-resource-count",
                "resource": "asg",
                "max-resources": 1,
                "filters": [{
                    "type": "image-age",
                    "op": "ge",
                    "days": 0
                }]
            },
            session_factory=session_factory)
        resources = p.run()
        self.assertTrue(resources)

    def test_policy_metrics(self):
        session_factory = self.replay_flight_data("test_policy_metrics")
        p = self.load_policy(
            {
                "name": "s3-encrypt-keys",
                "resource": "s3",
                "actions": [{"type": "encrypt-keys"}],
            },
            session_factory=session_factory,
        )

        end = datetime.now().replace(hour=0, minute=0, microsecond=0)
        start = end - timedelta(14)
        period = 24 * 60 * 60 * 14
        self.maxDiff = None
        self.assertEqual(
            json.loads(dumps(p.get_metrics(start, end, period), indent=2)),
            {
                "ActionTime": [
                    {
                        "Timestamp": "2016-05-30T00:00:00+00:00",
                        "Average": 8541.752702140668,
                        "Sum": 128126.29053211001,
                        "Unit": "Seconds",
                    }
                ],
                "Total Keys": [
                    {
                        "Timestamp": "2016-05-30T00:00:00+00:00",
                        "Average": 1575708.7333333334,
                        "Sum": 23635631.0,
                        "Unit": "Count",
                    }
                ],
                "ResourceTime": [
                    {
                        "Timestamp": "2016-05-30T00:00:00+00:00",
                        "Average": 8.682969363532667,
                        "Sum": 130.24454045299,
                        "Unit": "Seconds",
                    }
                ],
                "ResourceCount": [
                    {
                        "Timestamp": "2016-05-30T00:00:00+00:00",
                        "Average": 23.6,
                        "Sum": 354.0,
                        "Unit": "Count",
                    }
                ],
                "Unencrypted": [
                    {
                        "Timestamp": "2016-05-30T00:00:00+00:00",
                        "Average": 10942.266666666666,
                        "Sum": 164134.0,
                        "Unit": "Count",
                    }
                ],
            },
        )

    def test_get_resource_manager(self):
        collection = self.load_policy_set(
            {
                "policies": [
                    {
                        "name": "query-instances",
                        "resource": "ec2",
                        "filters": [{"tag-key": "CMDBEnvironment"}],
                    }
                ]
            }
        )
        p = collection.policies[0]
        self.assertTrue(isinstance(p.load_resource_manager(), EC2))

    def test_get_logs_from_group(self):
        p_data = {
            "name": "related-rds-test",
            "resource": "rds",
            "filters": [
                {"key": "GroupName", "type": "security-group", "value": "default"}
            ],
            "actions": [{"days": 10, "type": "retention"}],
        }
        session_factory = self.replay_flight_data("test_logs_from_group")
        config = {"log_group": "test-logs"}
        policy = self.load_policy(p_data, config, session_factory)
        logs = list(policy.get_logs("2016-11-01 00:00:00", "2016-11-30 11:59:59"))
        self.assertEqual(len(logs), 6)
        # entries look reasonable
        entry = logs[1]
        self.assertIn("timestamp", entry)
        self.assertIn("message", entry)
        # none in range
        logs = list(policy.get_logs("2016-10-01 00:00:00", "2016-10-31 11:59:59"))
        self.assertEqual(len(logs), 0)

    def xtest_policy_run(self):
        manager.resources.register("dummy", DummyResource)
        self.addCleanup(manager.resources.unregister, "dummy")
        self.output_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.output_dir)

        collection = self.load_policy_set(
            {"policies": [{"name": "process-instances", "resource": "dummy"}]},
            {"output_dir": self.output_dir},
        )
        p = collection.policies[0]
        p()
        self.assertEqual(len(p.ctx.metrics.data), 3)

    def test_validate_policy_start_stop(self):
        data = {
            'name': 'bad-str-parse',
            'resource': 'ec2',
            'start': 'asdf'
        }
        with self.assertRaises(ValueError):
            self.load_policy(data)

        data = {
            'name': 'bad-non-str-parse',
            'resource': 'ec2',
            'start': 2
        }
        with self.assertRaises(Exception):
            self.load_policy(data)

        data = {
            'name': 'bad-tz-parse',
            'resource': 'ec2',
            'tz': 'asdf'
        }
        with self.assertRaises(PolicyValidationError):
            self.load_policy(data)

        data = {
            'name': 'bad-tz-int-parse',
            'resource': 'ec2',
            'tz': 2
        }
        with self.assertRaises(Exception):
            self.load_policy(data)

        data = {
            'name': 'good-time-parse',
            'resource': 'ec2',
            'start': '4 AM'
        }
        p = self.load_policy(data)
        result = p.validate_policy_start_stop()
        self.assertEqual(result, None)

        data = {
            'name': 'good-tz-str-parse',
            'resource': 'ec2',
            'tz': 'UTC'
        }

        p = self.load_policy(data)
        result = p.validate_policy_start_stop()
        self.assertEqual(result, None)


class PolicyExecutionModeTest(BaseTest):

    def test_run_unimplemented(self):
        self.assertRaises(NotImplementedError, policy.PolicyExecutionMode({}).run)

    def test_get_logs_unimplemented(self):
        self.assertRaises(
            NotImplementedError, policy.PolicyExecutionMode({}).get_logs, 1, 2
        )


class LambdaModeTest(BaseTest):

    def test_tags_validation(self):
        log_file = self.capture_logging('c7n.policy', level=logging.INFO)
        self.load_policy({
            'name': 'foobar',
            'resource': 'aws.ec2',
            'mode': {
                'type': 'config-rule',
                'tags': {
                    'custodian-mode': 'xyz',
                    'xyz': 'bar'}
            }},
            validate=True)
        lines = log_file.getvalue().strip().split('\n')
        self.assertEqual(
            lines[0],
            ('Custodian reserves policy lambda tags starting with '
             'custodian - policy specifies custodian-mode'))

    def test_tags_injection(self):
        p = self.load_policy({
            'name': 'foobar',
            'resource': 'aws.ec2',
            'mode': {
                'type': 'config-rule',
                'tags': {
                    'xyz': 'bar'}
            }},
            validate=True)

        from c7n import mu
        policy_lambda = []

        def publish(self, func, alias=None, role=None, s3_uri=None):
            policy_lambda.append(func)

        self.patch(mu.LambdaManager, 'publish', publish)

        p.provision()
        self.assertEqual(
            policy_lambda[0].tags['custodian-info'],
            'mode=config-rule:version=%s' % version)


class PullModeTest(BaseTest):

    def test_skip_when_region_not_equal(self):
        log_file = self.capture_logging("custodian.policy")

        policy_name = "rds-test-policy"
        p = self.load_policy(
            {
                "name": policy_name,
                "resource": "rds",
                "region": "us-east-1",
                "filters": [{"type": "default-vpc"}],
            },
            config={"region": "us-west-2"},
            session_factory=None,
        )

        p.run()

        lines = log_file.getvalue().strip().split("\n")
        self.assertIn(
            "Skipping policy:{} target-region:us-east-1 current-region:us-west-2".format(
                policy_name
            ),
            lines,
        )

    def test_is_runnable_mismatch_region(self):
        p = self.load_policy(
            {'name': 'region-mismatch',
             'resource': 'ec2',
             'region': 'us-east-1'},
            config={'region': 'us-west-2', 'validate': True},
            session_factory=None)
        pull_mode = policy.PullMode(p)
        self.assertEqual(pull_mode.is_runnable(), False)

    def test_is_runnable_dates(self):
        p = self.load_policy(
            {'name': 'good-start-date',
             'resource': 'ec2',
             'tz': 'UTC',
             'start': '2018-3-29'},
            config={'validate': True},
            session_factory=None)
        pull_mode = policy.PullMode(p)
        self.assertEqual(pull_mode.is_runnable(), True)

        tomorrow_date = str(datetime.date(datetime.utcnow()) + timedelta(days=1))
        p = self.load_policy(
            {'name': 'bad-start-date',
             'resource': 'ec2',
             'tz': 'UTC',
             'start': tomorrow_date},
            config={'validate': True},
            session_factory=None)
        pull_mode = policy.PullMode(p)
        self.assertEqual(pull_mode.is_runnable(), False)

        p = self.load_policy(
            {'name': 'good-end-date',
             'resource': 'ec2',
             'tz': 'UTC',
             'end': tomorrow_date},
            config={'validate': True},
            session_factory=None)
        pull_mode = policy.PullMode(p)
        self.assertEqual(pull_mode.is_runnable(), True)

        p = self.load_policy(
            {'name': 'bad-end-date',
             'resource': 'ec2',
             'tz': 'UTC',
             'end': '2018-3-29'},
            config={'validate': True},
            session_factory=None)
        pull_mode = policy.PullMode(p)
        self.assertEqual(pull_mode.is_runnable(), False)

        p = self.load_policy(
            {'name': 'bad-start-end-date',
             'resource': 'ec2',
             'tz': 'UTC',
             'start': '2018-3-28',
             'end': '2018-3-29'},
            config={'validate': True},
            session_factory=None)
        pull_mode = policy.PullMode(p)
        self.assertEqual(pull_mode.is_runnable(), False)

    def test_is_runnable_parse_dates(self):
        p = self.load_policy(
            {'name': 'parse-date-policy',
             'resource': 'ec2',
             'tz': 'UTC',
             'start': 'March 3 2018'},
            config={'validate': True},
            session_factory=None)
        pull_mode = policy.PullMode(p)
        self.assertEqual(pull_mode.is_runnable(), True)

        p = self.load_policy(
            {'name': 'parse-date-policy',
             'resource': 'ec2',
             'tz': 'UTC',
             'start': 'March 3rd 2018'},
            config={'validate': True},
            session_factory=None)
        pull_mode = policy.PullMode(p)
        self.assertEqual(pull_mode.is_runnable(), True)

        p = self.load_policy(
            {'name': 'parse-date-policy',
             'resource': 'ec2',
             'tz': 'UTC',
             'start': '28 March 2018'},
            config={'validate': True},
            session_factory=None)
        pull_mode = policy.PullMode(p)
        self.assertEqual(pull_mode.is_runnable(), True)


class PhdModeTest(BaseTest):

    def test_validation(self):
        self.assertRaises(
            PolicyValidationError,
            self.load_policy,
            {'name': 'xyz', 'resource': 'ec2',
             'mode': {'type': 'phd'}})
        self.load_policy(
            {'name': 'abc', 'resource': 'account',
             'mode': {'type': 'phd'}})


class GuardModeTest(BaseTest):

    def test_unsupported_resource(self):
        self.assertRaises(
            ValueError,
            self.load_policy,
            {"name": "vpc", "resource": "vpc", "mode": {"type": "guard-duty"}},
            validate=True,
        )

    def test_lambda_policy_validate_name(self):
        name = "ec2-instance-guard-D8488F01-0E3E-4772-A3CB-E66EEBB9BDF4"
        with self.assertRaises(PolicyValidationError) as e_cm:
            self.load_policy(
                {"name": name,
                 "resource": "ec2",
                 "mode": {"type": "guard-duty"}},
                validate=True)
        self.assertTrue("max length with prefix" in str(e_cm.exception))

    @mock.patch("c7n.mu.LambdaManager.publish")
    def test_ec2_guard_event_pattern(self, publish):

        def assert_publish(policy_lambda, role):
            events = policy_lambda.get_events(mock.MagicMock())
            self.assertEqual(len(events), 1)
            pattern = json.loads(events[0].render_event_pattern())
            expected = {
                "source": ["aws.guardduty"],
                "detail": {"resource": {"resourceType": ["Instance"]}},
                "detail-type": ["GuardDuty Finding"],
            }
            self.assertEqual(pattern, expected)

        publish.side_effect = assert_publish
        p = self.load_policy(
            {
                "name": "ec2-instance-guard",
                "resource": "ec2",
                "mode": {"type": "guard-duty"},
            }
        )
        p.run()

    @mock.patch("c7n.mu.LambdaManager.publish")
    def test_iam_guard_event_pattern(self, publish):

        def assert_publish(policy_lambda, role):
            events = policy_lambda.get_events(mock.MagicMock())
            self.assertEqual(len(events), 1)
            pattern = json.loads(events[0].render_event_pattern())
            expected = {
                "source": ["aws.guardduty"],
                "detail": {"resource": {"resourceType": ["AccessKey"]}},
                "detail-type": ["GuardDuty Finding"],
            }
            self.assertEqual(pattern, expected)

        publish.side_effect = assert_publish
        p = self.load_policy(
            {
                "name": "iam-user-guard",
                "resource": "iam-user",
                "mode": {"type": "guard-duty"},
            }
        )
        p.run()

    @mock.patch("c7n.query.QueryResourceManager.get_resources")
    def test_ec2_instance_guard(self, get_resources):

        def instances(ids, cache=False):
            return [{"InstanceId": ids[0]}]

        get_resources.side_effect = instances

        p = self.load_policy(
            {
                "name": "ec2-instance-guard",
                "resource": "ec2",
                "mode": {"type": "guard-duty"},
            }
        )

        event = event_data("ec2-duty-event.json")
        results = p.push(event, None)
        self.assertEqual(results, [{"InstanceId": "i-99999999"}])

    @mock.patch("c7n.query.QueryResourceManager.get_resources")
    def test_iam_user_access_key_annotate(self, get_resources):

        def users(ids, cache=False):
            return [{"UserName": ids[0]}]

        get_resources.side_effect = users

        p = self.load_policy(
            {
                "name": "user-key-guard",
                "resource": "iam-user",
                "mode": {"type": "guard-duty"},
            }
        )

        event = event_data("iam-duty-event.json")
        results = p.push(event, None)
        self.assertEqual(
            results,
            [
                {
                    u"UserName": u"GeneratedFindingUserName",
                    u"c7n:AccessKeys": {u"AccessKeyId": u"GeneratedFindingAccessKeyId"},
                }
            ],
        )
