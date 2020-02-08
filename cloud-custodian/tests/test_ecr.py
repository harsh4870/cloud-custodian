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

from .common import BaseTest, functional
from botocore.exceptions import ClientError


class TestECR(BaseTest):

    def create_repository(self, client, name):
        """ Create the named repository. Delete existing one first if applicable. """
        existing_repos = {
            r["repositoryName"]
            for r in client.describe_repositories().get("repositories")
        }
        if name in existing_repos:
            client.delete_repository(repositoryName=name)

        client.create_repository(repositoryName=name)
        self.addCleanup(client.delete_repository, repositoryName=name)

    def test_ecr_set_scanning(self):
        factory = self.replay_flight_data('test_ecr_set_scanning')
        p = self.load_policy({
            'name': 'ecr-set-scanning',
            'resource': 'aws.ecr',
            'filters': [
                {'repositoryName': 'testrepo'},
                {'imageScanningConfiguration.scanOnPush': False}],
            'actions': ['set-scanning']}, session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['repositoryName'], 'testrepo')
        client = factory().client('ecr')
        repo = client.describe_repositories(repositoryNames=['testrepo'])[
            'repositories'][0]
        self.assertJmes(
            'imageScanningConfiguration.scanOnPush', repo, True)

    def test_ecr_set_immutability(self):
        factory = self.replay_flight_data('test_ecr_set_immutability')
        p = self.load_policy({
            'name': 'ecr-set-immutability',
            'resource': 'aws.ecr',
            'filters': [
                {'repositoryName': 'testrepo'},
                {'imageTagMutability': 'MUTABLE'}],
            'actions': [{'type': 'set-immutability'}]},
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['repositoryName'], 'testrepo')
        client = factory().client('ecr')
        repo = client.describe_repositories(repositoryNames=['testrepo'])[
            'repositories'][0]
        self.assertEqual(repo['imageTagMutability'], 'IMMUTABLE')

    def test_ecr_lifecycle_policy(self):
        session_factory = self.replay_flight_data('test_ecr_lifecycle_update')
        rule = {
            "rulePriority": 1,
            "description": "Expire images older than 14 days",
            "selection": {
                "tagStatus": "untagged",
                "countType": "sinceImagePushed",
                "countUnit": "days",
                "countNumber": 14
            },
            "action": {
                "type": "expire"
            }
        }
        p = self.load_policy({
            'name': 'ecr-update',
            'resource': 'aws.ecr',
            'filters': [
                {'repositoryName': 'c7n'},
                {'type': 'lifecycle-rule',
                 'state': False}],
            'actions': [{
                'type': 'set-lifecycle',
                'rules': [rule]}]},
            session_factory=session_factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
        client = session_factory().client('ecr')
        policy = json.loads(
            client.get_lifecycle_policy(
                repositoryName='c7n')['lifecyclePolicyText'])
        self.assertEqual(policy, {'rules': [rule]})

    def test_ecr_lifecycle_delete(self):
        session_factory = self.replay_flight_data('test_ecr_lifecycle_delete')
        p = self.load_policy({
            'name': 'ecr-update',
            'resource': 'aws.ecr',
            'filters': [
                {'repositoryName': 'c7n'},
                {'type': 'lifecycle-rule',
                 'state': True,
                 'match': [
                     {'action.type': 'expire'},
                     {'selection.tagStatus': 'untagged'}]}],
            'actions': [{
                'type': 'set-lifecycle',
                'state': False}]},
            session_factory=session_factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
        client = session_factory().client('ecr')
        self.assertRaises(
            client.exceptions.ClientError,
            client.get_lifecycle_policy,
            repositoryName='c7n')

    def test_ecr_tags(self):
        factory = self.replay_flight_data('test_ecr_tags')
        p = self.load_policy({
            'name': 'ecr-tag',
            'resource': 'ecr',
            'filters': [{'tag:Role': 'Dev'}],
            'actions': [
                {'type': 'tag',
                 'tags': {'Env': 'Dev'}},
                {'type': 'remove-tag',
                 'tags': ['Role']},
                {'type': 'mark-for-op',
                 'op': 'post-finding',
                 'days': 2}]},
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)

        client = factory().client('ecr')
        tags = {t['Key']: t['Value'] for t in
                client.list_tags_for_resource(
                    resourceArn=resources[0]['repositoryArn']).get('tags')}
        self.assertEqual(
            tags,
            {'Env': 'Dev',
             'maid_status': 'Resource does not meet policy: post-finding@2019/02/07'})

    @functional
    def test_ecr_no_policy(self):
        # running against a registry with no policy causes no issues.
        session_factory = self.replay_flight_data("test_ecr_no_policy")
        client = session_factory().client("ecr")
        name = "test-ecr-no-policy"
        self.create_repository(client, name)
        p = self.load_policy(
            {
                "name": "ecr-stat-3",
                "resource": "ecr",
                "filters": [{"repositoryName": name}],
                "actions": [{"type": "remove-statements", "statement_ids": ["abc"]}],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual([r["repositoryName"] for r in resources], [name])

    @functional
    def test_ecr_remove_matched(self):
        session_factory = self.replay_flight_data("test_ecr_remove_matched")
        client = session_factory().client("ecr")
        name = "test-ecr-remove-matched"
        self.create_repository(client, name)
        client.set_repository_policy(
            repositoryName=name,
            policyText=json.dumps(
                {
                    "Version": "2008-10-17",
                    "Statement": [
                        {
                            "Sid": "SpecificAllow",
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::185106417252:root"},
                            "Action": [
                                "ecr:GetDownloadUrlForLayer",
                                "ecr:BatchGetImage",
                                "ecr:BatchCheckLayerAvailability",
                                "ecr:ListImages",
                                "ecr:DescribeImages",
                            ],
                        },
                        {
                            "Sid": "Public",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": [
                                "ecr:GetDownloadUrlForLayer",
                                "ecr:BatchGetImage",
                                "ecr:BatchCheckLayerAvailability",
                            ],
                        },
                    ],
                }
            ),
        )

        p = self.load_policy(
            {
                "name": "ecr-stat-2",
                "resource": "ecr",
                "filters": [
                    {"repositoryName": name},
                    {"type": "cross-account", "whitelist": ["185106417252"]},
                ],
                "actions": [{"type": "remove-statements", "statement_ids": "matched"}],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual([r["repositoryName"] for r in resources], [name])
        data = json.loads(
            client.get_repository_policy(
                repositoryName=resources[0]["repositoryName"]
            ).get(
                "policyText"
            )
        )
        self.assertEqual(
            [s["Sid"] for s in data.get("Statement", ())], ["SpecificAllow"]
        )

    @functional
    def test_ecr_remove_named(self):
        # pre-requisites empty repo - no policy
        # pre-requisites abc repo - policy w/ matched statement id
        session_factory = self.replay_flight_data("test_ecr_remove_named")
        client = session_factory().client("ecr")
        name = "test-xyz"
        self.create_repository(client, name)
        client.set_repository_policy(
            repositoryName=name,
            policyText=json.dumps(
                {
                    "Version": "2008-10-17",
                    "Statement": [
                        {
                            "Sid": "WhatIsIt",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": ["ecr:Get*", "ecr:Batch*"],
                        }
                    ],
                }
            ),
        )

        p = self.load_policy(
            {
                "name": "ecr-stat",
                "resource": "ecr",
                "filters": [{"repositoryName": name}],
                "actions": [
                    {"type": "remove-statements", "statement_ids": ["WhatIsIt"]}
                ],
            },
            session_factory=session_factory,
        )

        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertRaises(
            ClientError,
            client.get_repository_policy,
            repositoryName=resources[0]["repositoryArn"],
        )

    def test_ecr_set_lifecycle(self):
        pass
