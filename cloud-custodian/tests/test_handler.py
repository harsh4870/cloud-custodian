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
import logging
import mock
import os

from .common import BaseTest
from c7n.exceptions import PolicyExecutionError
from c7n.policy import Policy
from c7n import handler


class HandleTest(BaseTest):

    def test_init_config_exec_option_merge(self):
        policy_config = {
            'execution-options': {
                'region': 'us-east-1',
                'assume_role': 'arn:::',
                'profile': 'dev',
                'tracer': 'xray',
                'account_id': '004',
                'dryrun': True,
                'cache': '/foobar.cache'},
            'policies': [
                {'mode': {
                    'type': 'period',
                    'schedule': "rate(1 minute)",
                    'execution-options': {
                        'metrics_enabled': True,
                        'assume_role': 'arn::::007:foo',
                        'output_dir': 's3://mybucket/output'}},
                 'resource': 'aws.ec2',
                 'name': 'check-dev'}
            ]}
        self.assertEqual(
            dict(handler.init_config(policy_config)),
            {'assume_role': 'arn::::007:foo',
             'metrics_enabled': 'aws',
             'tracer': 'xray',
             'account_id': '007',
             'region': 'us-east-1',
             'output_dir': 's3://mybucket/output',

             # defaults
             'external_id': None,
             'dryrun': False,
             'profile': None,
             'authorization_file': None,
             'cache': '',
             'regions': (),
             'cache_period': 0,
             'log_group': None,
             'metrics': None})

    def setupLambdaEnv(
            self, policy_data, environment=None, err_execs=(),
            log_level=logging.INFO):

        work_dir = self.change_cwd()
        self.patch(handler, 'policy_data', None)
        self.patch(handler, 'policy_config', None)

        # don't require api creds to resolve account id
        if 'execution-options' not in policy_data:
            policy_data['execution-options'] = {'account_id': '007'}
        elif 'account_id' not in policy_data['execution-options']:
            policy_data['execution-options']['account_id'] = '007'

        with open(os.path.join(work_dir, 'config.json'), 'w') as fh:
            json.dump(policy_data, fh, indent=2)
        output = self.capture_logging('custodian.lambda', level=log_level)
        if environment:
            self.change_environment(**environment)

        policy_execution = []
        validation_called = []

        def validate(self):
            validation_called.append(True)

        def push(self, event, context):
            policy_execution.append((event, context))
            if err_execs:
                raise err_execs.pop(0)

        self.patch(Policy, "push", push)
        self.patch(Policy, "validate", validate)
        return output, policy_execution

    def test_dispatch_log_event(self):
        output, executions = self.setupLambdaEnv(
            {'policies': [{'name': 'ec2', 'resource': 'ec2'}]},
            {'C7N_DEBUG_EVENT': None},
            log_level=logging.DEBUG)
        handler.dispatch_event({'detail': {'resource': 'xyz'}}, {})
        self.assertTrue('xyz' in output.getvalue())

        self.patch(handler, 'C7N_DEBUG_EVENT', False)
        handler.dispatch_event({'detail': {'resource': 'abc'}}, {})
        self.assertFalse('abc' in output.getvalue())
        self.assertTrue(executions)

    @mock.patch('c7n.handler.PolicyCollection')
    def test_dispatch_err_event(self, mock_collection):
        output, executions = self.setupLambdaEnv({
            'execution-options': {
                'output_dir': 's3://xyz',
                'account_id': '004'},
            'policies': [{'resource': 'ec2', 'name': 'xyz'}]},
            log_level=logging.DEBUG)

        mock_collection.from_data.return_value = []
        handler.dispatch_event({'detail': {'errorCode': 'unauthorized'}}, None)
        self.assertTrue('Skipping failed operation: unauthorized' in output.getvalue())
        self.patch(handler, 'C7N_SKIP_EVTERR', False)
        handler.dispatch_event({'detail': {'errorCode': 'foi'}}, None)
        self.assertFalse('Skipping failed operation: foi' in output.getvalue())
        mock_collection.from_data.assert_called_once()

    def test_dispatch_err_handle(self):
        output, executions = self.setupLambdaEnv({
            'execution-options': {'output_dir': 's3://xyz', 'account_id': '004'},
            'policies': [{'resource': 'ec2', 'name': 'xyz'}]},
            err_execs=[PolicyExecutionError("foo")] * 2)

        self.assertRaises(
            PolicyExecutionError,
            handler.dispatch_event,
            {'detail': {'xyz': 'oui'}}, None)

        self.patch(handler, 'C7N_CATCH_ERR', True)
        handler.dispatch_event({'detail': {'xyz': 'oui'}}, None)
        self.assertEqual(output.getvalue().count('error during'), 2)

    def test_handler(self):
        output, executions = self.setupLambdaEnv({
            'policies': [{
                'resource': 'asg', 'name': 'auto'}]},
        )

        self.assertEqual(
            handler.dispatch_event({"detail": {"errorCode": "404"}}, None), None
        )
        self.assertEqual(handler.dispatch_event({"detail": {}}, None), True)
        self.assertEqual(executions, [({"detail": {}, "debug": True}, None)])
