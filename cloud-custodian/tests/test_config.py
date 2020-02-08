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

from c7n.exceptions import PolicyValidationError
from .common import BaseTest


class ConfigRecorderTest(BaseTest):

    def test_config_recorder(self):
        factory = self.replay_flight_data('test_config_recorder')
        p = self.load_policy({
            'name': 'recorder',
            'resource': 'aws.config-recorder',
            'filters': [
                {'recordingGroup.allSupported': True},
                {'recordingGroup.includeGlobalResourceTypes': True},
                {'deliveryChannel.name': 'default'}]},
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['name'], 'default')


class ConfigComplianceTest(BaseTest):

    def test_compliance(self):
        factory = self.replay_flight_data('test_config_compliance')
        p = self.load_policy({
            'name': 'compliance',
            'resource': 'ebs',
            'filters': [
                {'type': 'config-compliance',
                 'eval_filters': [{
                     'EvaluationResultIdentifier.EvaluationResultQualifier.ResourceType': 'AWS::EC2::Volume'}], # noqa
                 'rules': ['custodian-good-vol']}
            ]}, session_factory=factory, config={'region': 'us-east-2'})
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['VolumeId'], 'vol-0c6efd2a9f5677a03')
        self.assertEqual(resources[0]['c7n:config-compliance'][0]['Annotation'],
                         'Resource is not compliant with policy:good-vol')


class ConfigRuleTest(BaseTest):

    def test_validate(self):
        with self.assertRaises(PolicyValidationError) as ecm:
            self.load_policy({
                'name': 'rule',
                'resource': 'ebs-snapshot',
                'mode': {
                    'role': 'arn:aws:iam',
                    'type': 'config-rule'}})
        self.assertIn('AWS Config does not support resource-type:ebs-snapshot',
                      str(ecm.exception))

    def test_status(self):
        session_factory = self.replay_flight_data("test_config_rule_status")
        p = self.load_policy(
            {
                "name": "rule",
                "resource": "config-rule",
                "filters": [
                    {"type": "status", "key": "FirstEvaluationStarted", "value": True}
                ],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 3)
        self.assertEqual(
            set(
                (
                    "custodian-bucket-tags",
                    "custodian-bucket-ver-tags",
                    "custodian-db-tags",
                )
            ),
            {r["ConfigRuleName"] for r in resources},
        )

    def test_delete(self):
        session_factory = self.replay_flight_data("test_config_rule_delete")
        p = self.load_policy(
            {
                "name": "rule",
                "resource": "config-rule",
                "filters": [{"ConfigRuleName": "custodian-db-tags"}],
                "actions": ["delete"],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        cr = resources.pop()
        client = session_factory().client("config")
        rules = client.describe_config_rules(
            ConfigRuleNames=[cr["ConfigRuleName"]]
        ).get(
            "ConfigRules", []
        )
        self.assertEqual(rules[0]["ConfigRuleState"], "DELETING")
