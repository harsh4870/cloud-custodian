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

from botocore.exceptions import ClientError

from .common import BaseTest


class TestRestAccount(BaseTest):

    def test_missing_rest_account(self):
        session_factory = self.replay_flight_data("test_rest_account_missing")
        p = self.load_policy(
            {"name": "api-account", "resource": "rest-account"},
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(resources, [])

    def test_rest_api_update(self):
        session_factory = self.replay_flight_data("test_rest_account_update")
        log_role = "arn:aws:iam::644160558196:role/OtherApiGatewayLogger"
        p = self.load_policy(
            {
                "name": "update-account",
                "resource": "rest-account",
                "actions": [
                    {
                        "type": "update",
                        "patch": [
                            {
                                "op": "replace",
                                "path": "/cloudwatchRoleArn",
                                "value": log_role,
                            }
                        ],
                    }
                ],
            },
            session_factory=session_factory,
        )
        before_account, = p.resource_manager._get_account()
        self.assertEqual(
            before_account["cloudwatchRoleArn"],
            "arn:aws:iam::644160558196:role/ApiGwLogger",
        )

        resources = p.run()
        self.assertEqual(len(resources), 1)

        after_account, = p.resource_manager._get_account()
        self.assertEqual(after_account["cloudwatchRoleArn"], log_role)


class TestRestApi(BaseTest):

    def test_rest_api_update(self):
        session_factory = self.replay_flight_data('test_rest_api_update')
        p = self.load_policy({
            'name': 'update-api',
            'resource': 'rest-api',
            'filters': [
                {'name': 'testapi'},
                {'description': 'for demo only'}
            ],
            'actions': [{
                'type': 'update',
                'patch': [{
                    'op': 'replace',
                    'path': '/description',
                    'value': 'for replacement'}]
            }],
        }, session_factory=session_factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)

        updated = session_factory().client('apigateway').get_rest_api(
            restApiId=resources[0]['id'])
        self.assertEqual(updated['description'], 'for replacement')

    def test_rest_api_tag_untag_mark(self):
        session_factory = self.replay_flight_data('test_rest_api_tag_untag_mark')
        client = session_factory().client("apigateway")
        tags = client.get_tags(resourceArn='arn:aws:apigateway:us-east-1::/restapis/dj7uijzv27')
        self.assertEqual(tags.get('tags', {}),
            {'target-tag': 'pratyush'})
        self.maxDiff = None
        p = self.load_policy({
            'name': 'tag-rest-api',
            'resource': 'rest-api',
            'filters': [{'type': 'value', 'key': 'id', 'value': 'dj7uijzv27'}],
            "actions": [
                {'type': 'tag',
                'tags': {'Env': 'Dev'}},
                {'type': 'remove-tag',
                'tags': ['target-tag']},
                {'type': 'mark-for-op', 'tag': 'custodian_cleanup',
                'op': 'update',
                'days': 2}
            ]},
            session_factory=session_factory)
        resources = p.run()
        self.assertTrue(len(resources), 1)
        tags = client.get_tags(resourceArn='arn:aws:apigateway:us-east-1::/restapis/dj7uijzv27')
        self.assertEqual(tags.get('tags', {}),
            {'Env': 'Dev',
            'custodian_cleanup': 'Resource does not meet policy: update@2019/09/11'})

    def test_rest_api_delete(self):
        session_factory = self.replay_flight_data('test_rest_api_delete')
        p = self.load_policy({
            'name': 'tag-rest-api',
            'resource': 'rest-api',
            'filters': [{'tag:target-tag': 'pratyush'}],
            "actions": [{"type": "delete"}]},
            session_factory=session_factory)
        resources = p.run()
        self.assertTrue(len(resources), 1)
        self.assertTrue(resources[0]['id'], 'am0c2fyskg')
        client = session_factory().client("apigateway")
        with self.assertRaises(ClientError) as e:
            client.delete_rest_api(restApiId='am0c2fyskg')
        self.assertEqual(e.exception.response['Error']['Code'], 'NotFoundException')


class TestRestResource(BaseTest):

    def test_rest_resource_query(self):
        session_factory = self.replay_flight_data("test_rest_resource_resource")
        p = self.load_policy(
            {"name": "all-rest-resources", "resource": "rest-resource"},
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(
            sorted([(r["restApiId"], r["path"]) for r in resources]),
            [
                ("5xhc1cnb7h", "/"),
                ("5xhc1cnb7h", "/{proxy+}"),
                ("rtmgxfiay5", "/"),
                ("rtmgxfiay5", "/glenns_test"),
            ],
        )

    def test_rest_integration_filter(self):
        session_factory = self.replay_flight_data("test_rest_integration_filter")
        p = self.load_policy(
            {
                "name": "rest-integration-filter",
                "resource": "aws.rest-resource",
                "filters": [
                    {
                        "type": "rest-integration",
                        "key": "type",
                        "value": "AWS",
                    }
                ],
            }, session_factory=session_factory)

        resources = p.run()

        if len(resources) == 1:
            integrations = resources[0].get('c7n:matched-method-integrations', [])
            if len(integrations) == 1:
                self.assertEqual(integrations[0]['resourceId'], 'ovgcc9m0b7')
            else:
                self.assertFail()
        else:
            self.assertFail()

    def test_rest_integration_delete(self):
        session_factory = self.replay_flight_data("test_rest_integration_delete")
        p = self.load_policy(
            {
                "name": "rest-integration-delete",
                "resource": "rest-resource",
                "filters": [{"type": "rest-integration", "key": "type", "value": "AWS"}],
                "actions": [{"type": "delete-integration"}],
            },
            session_factory=session_factory,
        )
        resources = p.run()

        client = session_factory().client("apigateway")
        integrations = resources[0].get("c7n:matched-method-integrations", [])

        with self.assertRaises(ClientError) as e:
            client.get_integration(
                restApiId=integrations[0]["restApiId"],
                resourceId=integrations[0]['resourceId'],
                httpMethod=integrations[0]["resourceHttpMethod"]
            )
        self.assertEqual(e.exception.response['Error']['Code'], 'NotFoundException')

    def test_rest_integration_update(self):
        session_factory = self.replay_flight_data("test_rest_integration_update")
        p = self.load_policy(
            {
                "name": "rest-integration-update",
                "resource": "rest-resource",
                "filters": [
                    {
                        "type": "rest-integration",
                        "key": "timeoutInMillis",
                        "value": "29000",
                        "op": "not-equal",
                    }
                ],
                "actions": [
                    {
                        "type": "update-integration",
                        "patch": [
                            {
                                "op": "replace",
                                "path": "/timeoutInMillis",
                                "value": "29000",
                            }
                        ],
                    }
                ],
            },
            session_factory=session_factory,
        )
        resources = p.run()

        self.assertEqual(len(resources), 1)
        integrations = []
        for r in resources:
            integrations.extend(r["c7n:matched-method-integrations"])

        i = integrations.pop()

        client = session_factory().client("apigateway")

        method = client.get_method(
            restApiId=i["restApiId"],
            resourceId=i["resourceId"],
            httpMethod=i["resourceHttpMethod"],
        )
        self.assertEqual(method['methodIntegration']['timeoutInMillis'], 29000)

    def test_rest_resource_method_update(self):
        session_factory = self.replay_flight_data("test_rest_resource_method_update")
        p = self.load_policy(
            {
                "name": "rest-method-iam",
                "resource": "rest-resource",
                "filters": [
                    {
                        "type": "rest-method",
                        "key": "authorizationType",
                        "value": "AWS_IAM",
                        "op": "not-equal",
                    }
                ],
                "actions": [
                    {
                        "type": "update-method",
                        "patch": [
                            {
                                "op": "replace",
                                "path": "/authorizationType",
                                "value": "AWS_IAM",
                            }
                        ],
                    }
                ],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        methods = []
        for r in resources:
            methods.extend(r["c7n:matched-resource-methods"])

        m = methods.pop()
        client = session_factory().client("apigateway")

        method = client.get_method(
            restApiId=m["restApiId"],
            resourceId=m["resourceId"],
            httpMethod=m["httpMethod"],
        )
        self.assertEqual(method["authorizationType"], "AWS_IAM")


class TestRestStage(BaseTest):

    def test_rest_stage_resource(self):
        session_factory = self.replay_flight_data("test_rest_stage")
        p = self.load_policy(
            {
                "name": "all-rest-stages",
                "resource": "rest-stage",
                "filters": [{"tag:ENV": "DEV"}],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["stageName"], "latest")

    def test_rest_stage_update(self):
        session_factory = self.replay_flight_data("test_rest_stage_update")
        p = self.load_policy(
            {
                "name": "rest-stage-update",
                "resource": "rest-stage",
                "filters": [{'methodSettings."*/*".loggingLevel': "absent"}],
                "actions": [
                    {
                        "type": "update",
                        "patch": [
                            {
                                "op": "replace",
                                "path": "/*/*/logging/dataTrace",
                                "value": "true",
                            },
                            {
                                "op": "replace",
                                "path": "/*/*/logging/loglevel",
                                "value": "info",
                            },
                        ],
                    }
                ],
            },
            session_factory=session_factory,
        )

        resources = p.run()
        self.assertEqual(len(resources), 2)
        client = session_factory().client("apigateway")

        stage = client.get_stage(
            restApiId=resources[0]["restApiId"], stageName=resources[0]["stageName"]
        )

        found = False
        for k, m in stage.get("methodSettings", {}).items():
            found = True
            self.assertEqual(m["loggingLevel"], "INFO")
            self.assertEqual(m["dataTraceEnabled"], True)
        self.assertTrue(found)

    def test_rest_stage_delete(self):
        session_factory = self.replay_flight_data("test_rest_stage_delete")
        p = self.load_policy(
            {
                "name": "rest-stage-delete",
                "resource": "rest-stage",
                "filters": [{"type": "value", "key": "stageName", "value": "delete-test"}],
                "actions": [{"type": "delete"}],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        client = session_factory().client("apigateway")
        with self.assertRaises(ClientError) as e:
            client.get_stage(
                restApiId=resources[0]["restApiId"], stageName=resources[0]["stageName"]
            )
        self.assertEqual(e.exception.response['Error']['Code'], 'NotFoundException')

    def test_rest_stage_tag_untag_mark(self):
        session_factory = self.replay_flight_data('test_rest_stage_tag_untag_mark')
        client = session_factory().client("apigateway")
        tags = client.get_tags(
            resourceArn='arn:aws:apigateway:us-east-1::/restapis/l5paassc1h/stages/test')
        self.assertEqual(tags.get('tags', {}),
            {'target-tag': 'pratyush'})
        p = self.load_policy({
            'name': 'tag-rest-stage',
            'resource': 'rest-stage',
            'filters': [{'tag:target-tag': 'pratyush'}],
            "actions": [
                {'type': 'tag',
                'tags': {'Env': 'Dev'}},
                {'type': 'remove-tag',
                'tags': ['target-tag']},
                {'type': 'mark-for-op', 'tag': 'custodian_cleanup',
                'op': 'update',
                'days': 2}
            ]},
            session_factory=session_factory)
        resources = p.run()
        self.assertTrue(len(resources), 1)
        tags = client.get_tags(
            resourceArn='arn:aws:apigateway:us-east-1::/restapis/l5paassc1h/stages/test')
        self.assertEqual(tags.get('tags', {}),
            {'Env': 'Dev',
            'custodian_cleanup': 'Resource does not meet policy: update@2019/11/04'})
