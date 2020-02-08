# Copyright 2017 Capital One Services, LLC
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
import time

from c7n.exceptions import PolicyValidationError

from .common import BaseTest, functional


class TestOpsCenter(BaseTest):

    def test_post_ops_item(self):
        factory = self.replay_flight_data('test_post_ops_item')
        p = self.load_policy({
            'name': 'checking-lambdas',
            'description': 'something good',
            'resource': 'aws.lambda',
            'source': 'config',
            'query': [
                {'clause': "resourceId = 'custodian-aws'"}],
            'actions': [{
                'type': 'post-item'}]},
            session_factory=factory, config={'region': 'us-east-1'})
        resources = p.run()
        client = factory().client('ssm', region_name='us-east-1')
        item = client.get_ops_item(
            OpsItemId=resources[0]['c7n:opsitem']).get('OpsItem')
        arn = p.resource_manager.get_arns(resources)[0]
        self.assertTrue(
            arn in item['OperationalData']['/aws/resources']['Value'])
        self.assertTrue(item['OperationalData']['/aws/dedup'])
        self.assertEqual(item['Title'], p.name)
        self.assertEqual(item['Description'], p.data['description'])

    def test_ops_item_filter(self):
        factory = self.replay_flight_data('test_ops_item_filter')
        p = self.load_policy({
            'name': 'checking-lambdas',
            'description': 'something good',
            'resource': 'aws.lambda',
            'source': 'config',
            'query': [
                {'clause': "resourceId = 'custodian-aws'"}],
            'filters': [{
                'type': 'ops-item',
                'priority': [3, 4, 5],
                'title': 'checking-lambdas',
                'source': 'Cloud Custodian',
            }]},
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(
            resources[0]['c7n:opsitems'],
            ['oi-9be57440dcb3'])

    def test_post_ops_item_update(self):
        factory = self.replay_flight_data('test_post_ops_item_update')
        p = self.load_policy({
            'name': 'checking-lambdas',
            'description': 'something good',
            'resource': 'aws.lambda',
            'source': 'config',
            'query': [
                {'clause': "resourceId = 'custodian-nuke-emr'"}],
            'actions': [{
                'type': 'post-item'}]},
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
        client = factory().client('ssm', region_name='us-east-1')
        item = client.get_ops_item(
            OpsItemId=resources[0]['c7n:opsitem']).get('OpsItem')
        self.assertEqual(
            json.loads(item['OperationalData']['/aws/resources']['Value']),
            [{'arn': 'arn:aws:lambda:us-east-1::function:custodian-aws'},
             {'arn': 'arn:aws:lambda:us-east-1::function:custodian-nuke-emr'}])

    def test_update_ops_item(self):
        factory = self.replay_flight_data('test_update_ops_item')
        p = self.load_policy({
            'name': 'checking-lambdas',
            'description': 'something good',
            'resource': 'aws.ops-item',
            'query': [
                {'Key': 'Status', 'Operator': 'Equal', 'Values': ['Open']}
            ],
            'actions': [{
                'type': 'update',
                'topics': ['arn:aws:sns:us-west-2:644160558196:aws-command'],
                'status': 'Resolved',
            }]},
            config={'region': 'us-west-2'},
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
        client = factory().client('ssm', region_name='us-west-2')
        if self.recording:
            time.sleep(5)
        item = client.get_ops_item(
            OpsItemId=resources[0]['OpsItemId'])['OpsItem']
        self.assertEqual(item['Status'], 'Resolved')
        self.assertEqual(
            item['Notifications'],
            [{'Arn': 'arn:aws:sns:us-west-2:644160558196:aws-command'}])

    def test_invalid_resource_query(self):
        self.assertRaises(
            PolicyValidationError, self.load_policy,
            {'name': 'value',
             'resource': 'aws.ops-item',
             'query': [
                 {'Key': 'Status', 'Operator': 'Equals', 'Values': ['Open']}]},
            validate=True)

    def test_get_resources(self):
        factory = self.replay_flight_data('test_ops_item_get_resources')
        p = self.load_policy({
            'name': 'foo',
            'resource': 'aws.ops-item'},
            session_factory=factory,
            config={'region': 'us-east-1'})
        resources = p.resource_manager.get_resources('oi-5aa4c36439ed')
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['OpsItemId'], 'oi-5aa4c36439ed')


class TestSSM(BaseTest):

    def test_ec2_ssm_send_command_validate(self):
        self.assertRaises(
            PolicyValidationError,
            self.load_policy,
            {'name': 'ssm-instances',
             'resource': 'aws.ec2',
             'actions': [
                 {'type': 'send-command',
                  'command': {
                      'DocumentName': 'AWS-RunShellScript'}}]},
            validate=True)

    def test_ssm_send_command(self):
        factory = self.replay_flight_data('test_ssm_send_command')
        p = self.load_policy({
            'name': 'ssm-instances',
            'resource': 'ssm-managed-instance',
            'filters': [{"PingStatus": "Online"}],
            'actions': [
                {'type': 'send-command',
                 'command': {
                     'DocumentName': 'AWS-RunShellScript',
                     'Parameters': {
                         'commands': [
                             'wget https://pkg.osquery.io/deb/osquery_3.3.0_1.linux.amd64.deb',
                             'dpkg -i osquery_3.3.0_1.linux.amd64.deb']}}}]},
            session_factory=factory, config={'region': 'us-east-2'})
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertTrue('c7n:SendCommand' in resources[0])

        if self.recording:
            time.sleep(5)

        result = factory().client('ssm').get_command_invocation(
            InstanceId=resources[0]['InstanceId'],
            CommandId=resources[0]['c7n:SendCommand'][0])
        self.assertEqual(result['Status'], 'Success')

    @functional
    def test_ssm_parameter_not_secure(self):
        session_factory = self.replay_flight_data("test_ssm_parameter_not_secure")
        client = session_factory().client("ssm")

        client.put_parameter(Name='test-name',
                             Type='String',
                             Overwrite=True,
                             Value='test-value')

        client.put_parameter(Name='secure-test-name',
                             Type='SecureString',
                             Overwrite=True,
                             Value='secure-test-value')

        p = self.load_policy(
            {
                "name": "ssm-parameter-not-secure",
                "resource": "ssm-parameter",
                "filters": [{"type": "value",
                             "op": "ne",
                             "key": "Type",
                             "value": "SecureString"}]
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.addCleanup(client.delete_parameters, Names=['test-name', 'secure-test-name'])

    def test_ssm_activation_expired(self):
        session_factory = self.replay_flight_data("test_ssm_activation_expired")
        p = self.load_policy(
            {
                "name": "ssm-list-expired-activations",
                "resource": "ssm-activation",
                "filters": [{"type": "value",
                             "key": "Expired",
                             "value": True}]
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 2)

    def test_ssm_get_manager_instances(self):
        session_factory = self.replay_flight_data("test_ssm_get_managed_instances")
        p = self.load_policy(
            {
                "name": "ssm-get-managed-instances",
                "resource": "ssm-managed-instance"
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["InstanceId"], "mi-1111aa111aa11a111")
