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
from c7n.utils import yaml_load


class TestSNS(BaseTest):

    @functional
    def test_sns_remove_matched(self):
        session_factory = self.replay_flight_data("test_sns_remove_matched")
        client = session_factory().client("sns")
        name = "test-sns-remove-matched"
        topic_arn = client.create_topic(Name=name)["TopicArn"]
        self.addCleanup(client.delete_topic, TopicArn=topic_arn)

        client.set_topic_attributes(
            TopicArn=topic_arn,
            AttributeName="Policy",
            AttributeValue=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "SpecificAllow",
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::644160558196:root"},
                            "Action": ["SNS:Subscribe"],
                            "Resource": topic_arn,
                        },
                        {
                            "Sid": "Public",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": ["SNS:GetTopicAttributes"],
                            "Resource": topic_arn,
                        },
                    ],
                }
            ),
        )

        p = self.load_policy(
            {
                "name": "sns-rm-matched",
                "resource": "sns",
                "filters": [
                    {"TopicArn": topic_arn},
                    {"type": "cross-account", "whitelist": ["123456789012"]},
                ],
                "actions": [{"type": "remove-statements", "statement_ids": "matched"}],
            },
            session_factory=session_factory,
        )
        resources = p.run()

        self.assertEqual([r["TopicArn"] for r in resources], [topic_arn])

        data = json.loads(
            client.get_topic_attributes(TopicArn=resources[0]["TopicArn"])[
                "Attributes"
            ][
                "Policy"
            ]
        )
        self.assertEqual(
            [s["Sid"] for s in data.get("Statement", ())], ["SpecificAllow"]
        )

    @functional
    def test_sns_remove_named(self):
        session_factory = self.replay_flight_data("test_sns_remove_named")
        client = session_factory().client("sns")
        name = "test-sns-remove-named"
        topic_arn = client.create_topic(Name=name)["TopicArn"]
        self.addCleanup(client.delete_topic, TopicArn=topic_arn)

        client.set_topic_attributes(
            TopicArn=topic_arn,
            AttributeName="Policy",
            AttributeValue=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "SpecificAllow",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": ["SNS:Subscribe"],
                            "Resource": topic_arn,
                        },
                        {
                            "Sid": "RemoveMe",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": ["SNS:GetTopicAttributes"],
                            "Resource": topic_arn,
                        },
                    ],
                }
            ),
        )

        p = self.load_policy(
            {
                "name": "sns-rm-named",
                "resource": "sns",
                "filters": [{"TopicArn": topic_arn}],
                "actions": [
                    {"type": "remove-statements", "statement_ids": ["RemoveMe"]}
                ],
            },
            session_factory=session_factory,
        )

        resources = p.run()
        self.assertEqual(len(resources), 1)

        data = json.loads(
            client.get_topic_attributes(TopicArn=resources[0]["TopicArn"])[
                "Attributes"
            ][
                "Policy"
            ]
        )
        self.assertTrue("RemoveMe" not in [s["Sid"] for s in data.get("Statement", ())])

    @functional
    def test_sns_modify_replace_policy(self):
        session_factory = self.replay_flight_data("test_sns_modify_replace_policy")
        client = session_factory().client("sns")
        name = "test_sns_modify_replace_policy"
        topic_arn = client.create_topic(Name=name)["TopicArn"]
        self.addCleanup(client.delete_topic, TopicArn=topic_arn)

        client.set_topic_attributes(
            TopicArn=topic_arn,
            AttributeName="Policy",
            AttributeValue=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "SpecificAllow",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": ["SNS:Subscribe"],
                            "Resource": topic_arn,
                        }
                    ],
                }
            ),
        )

        p = self.load_policy(
            {
                "name": "sns-modify-replace-policy",
                "resource": "sns",
                "filters": [{"TopicArn": topic_arn}],
                "actions": [
                    {
                        "type": "modify-policy",
                        "add-statements": [
                            {
                                "Sid": "ReplaceWithMe",
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": ["SNS:GetTopicAttributes"],
                                "Resource": topic_arn,
                            }
                        ],
                        "remove-statements": "*",
                    }
                ],
            },
            session_factory=session_factory,
        )

        resources = p.run()
        self.assertEqual(len(resources), 1)

        data = json.loads(
            client.get_topic_attributes(TopicArn=resources[0]["TopicArn"])[
                "Attributes"
            ][
                "Policy"
            ]
        )
        self.assertTrue(
            "ReplaceWithMe" in [s["Sid"] for s in data.get("Statement", ())]
        )

    @functional
    def test_sns_account_id_template(self):
        session_factory = self.replay_flight_data("test_sns_account_id_template")
        client = session_factory().client("sns")
        name = "test_sns_account_id_template"
        topic_arn = client.create_topic(Name=name)["TopicArn"]
        self.addCleanup(client.delete_topic, TopicArn=topic_arn)

        client.set_topic_attributes(
            TopicArn=topic_arn,
            AttributeName="Policy",
            AttributeValue=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "SpecificAllow",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": ["SNS:Subscribe"],
                            "Resource": topic_arn,
                        }
                    ],
                }
            ),
        )

        p = self.load_policy(
            {
                "name": "sns-modify-replace-policy",
                "resource": "sns",
                "filters": [{"TopicArn": topic_arn}],
                "actions": [
                    {
                        "type": "modify-policy",
                        "add-statements": [
                            {
                                "Sid": "__default_statement_ID_{account_id}",
                                "Effect": "Allow",
                                "Principal": {"Service": "s3.amazonaws.com"},
                                "Action": "SNS:Publish",
                                "Resource": topic_arn,
                                "Condition": {
                                    "StringEquals": {
                                        "AWS:SourceAccount": "{account_id}"
                                    },
                                    "ArnLike": {"aws:SourceArn": "arn:aws:s3:*:*:*"},
                                },
                            }
                        ],
                        "remove-statements": "*",
                    }
                ],
            },
            session_factory=session_factory,
        )

        resources = p.run()
        self.assertEqual(len(resources), 1)

        data = json.loads(
            client.get_topic_attributes(TopicArn=resources[0]["TopicArn"])[
                "Attributes"
            ][
                "Policy"
            ]
        )
        self.assertTrue(
            "__default_statement_ID_" +
            self.account_id in [s["Sid"] for s in data.get("Statement", ())]
        )

    @functional
    def test_sns_modify_remove_policy(self):
        session_factory = self.replay_flight_data("test_sns_modify_remove_policy")
        client = session_factory().client("sns")
        name = "test_sns_modify_remove_policy"
        topic_arn = client.create_topic(Name=name)["TopicArn"]
        self.addCleanup(client.delete_topic, TopicArn=topic_arn)

        client.set_topic_attributes(
            TopicArn=topic_arn,
            AttributeName="Policy",
            AttributeValue=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "SpecificAllow",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": ["SNS:Subscribe"],
                            "Resource": topic_arn,
                        },
                        {
                            "Sid": "RemoveMe",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": ["SNS:GetTopicAttributes"],
                            "Resource": topic_arn,
                        },
                    ],
                }
            ),
        )

        p = self.load_policy(
            {
                "name": "sns-modify-remove-policy",
                "resource": "sns",
                "filters": [{"TopicArn": topic_arn}],
                "actions": [
                    {
                        "type": "modify-policy",
                        "add-statements": [],
                        "remove-statements": ["RemoveMe"],
                    }
                ],
            },
            session_factory=session_factory,
        )

        resources = p.run()
        self.assertEqual(len(resources), 1)

        data = json.loads(
            client.get_topic_attributes(TopicArn=resources[0]["TopicArn"])[
                "Attributes"
            ][
                "Policy"
            ]
        )
        self.assertTrue("RemoveMe" not in [s["Sid"] for s in data.get("Statement", ())])

    @functional
    def test_sns_modify_add_policy(self):
        session_factory = self.replay_flight_data("test_sns_modify_add_policy")
        client = session_factory().client("sns")
        name = "test_sns_modify_add_policy"
        topic_arn = client.create_topic(Name=name)["TopicArn"]
        self.addCleanup(client.delete_topic, TopicArn=topic_arn)

        client.set_topic_attributes(
            TopicArn=topic_arn,
            AttributeName="Policy",
            AttributeValue=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "SpecificAllow",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": ["SNS:Subscribe"],
                            "Resource": topic_arn,
                        }
                    ],
                }
            ),
        )

        p = self.load_policy(
            {
                "name": "sns-modify-add-policy",
                "resource": "sns",
                "filters": [{"TopicArn": topic_arn}],
                "actions": [
                    {
                        "type": "modify-policy",
                        "add-statements": [
                            {
                                "Sid": "AddMe",
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": ["SNS:GetTopicAttributes"],
                                "Resource": topic_arn,
                            }
                        ],
                        "remove-statements": [],
                    }
                ],
            },
            session_factory=session_factory,
        )

        resources = p.run()
        self.assertEqual(len(resources), 1)

        data = json.loads(
            client.get_topic_attributes(TopicArn=resources[0]["TopicArn"])[
                "Attributes"
            ][
                "Policy"
            ]
        )
        self.assertTrue("AddMe" in [s["Sid"] for s in data.get("Statement", ())])

    @functional
    def test_sns_modify_add_and_remove_policy(self):
        session_factory = self.replay_flight_data(
            "test_sns_modify_add_and_remove_policy"
        )
        client = session_factory().client("sns")
        name = "test_sns_modify_add_and_remove_policy"
        topic_arn = client.create_topic(Name=name)["TopicArn"]
        self.addCleanup(client.delete_topic, TopicArn=topic_arn)

        client.set_topic_attributes(
            TopicArn=topic_arn,
            AttributeName="Policy",
            AttributeValue=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "SpecificAllow",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": ["SNS:Subscribe"],
                            "Resource": topic_arn,
                        },
                        {
                            "Sid": "RemoveMe",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": ["SNS:GetTopicAttributes"],
                            "Resource": topic_arn,
                        },
                    ],
                }
            ),
        )

        p = self.load_policy(
            {
                "name": "sns-modify-add-and-remove-policy",
                "resource": "sns",
                "filters": [{"TopicArn": topic_arn}],
                "actions": [
                    {
                        "type": "modify-policy",
                        "add-statements": [
                            {
                                "Sid": "AddMe",
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": ["SNS:GetTopicAttributes"],
                                "Resource": topic_arn,
                            }
                        ],
                        "remove-statements": ["RemoveMe"],
                    }
                ],
            },
            session_factory=session_factory,
        )

        resources = p.run()
        self.assertEqual(len(resources), 1)

        data = json.loads(
            client.get_topic_attributes(TopicArn=resources[0]["TopicArn"])[
                "Attributes"
            ][
                "Policy"
            ]
        )
        statement_ids = {s["Sid"] for s in data.get("Statement", ())}
        self.assertTrue("AddMe" in statement_ids)
        self.assertTrue("RemoveMe" not in statement_ids)
        self.assertTrue("SpecificAllow" in statement_ids)

    def test_sns_topic_encryption(self):
        session_factory = self.replay_flight_data('test_sns_kms_related_filter_test')
        kms = session_factory().client('kms')
        p = self.load_policy(
            {
                'name': 'test-sns-kms-related-filter',
                'resource': 'sns',
                'filters': [
                    {
                        'TopicArn': 'arn:aws:sns:us-east-1:644160558196:test'
                    },
                    {
                        'type': 'kms-key',
                        'key': 'c7n:AliasName',
                        'value': 'alias/skunk/trails'
                    }
                ]
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertTrue(len(resources), 1)
        aliases = kms.list_aliases(KeyId=resources[0]['KmsMasterKeyId'])
        self.assertEqual(aliases['Aliases'][0]['AliasName'], 'alias/skunk/trails')

    def test_set_sns_topic_encryption(self):
        session_factory = self.replay_flight_data('test_sns_set_encryption')
        topic = 'arn:aws:sns:us-west-1:644160558196:test'
        p = self.load_policy(
            {
                'name': 'test-sns-kms-related-filter',
                'resource': 'sns',
                'filters': [
                    {
                        'TopicArn': topic
                    },
                    {
                        'KmsMasterKeyId': 'absent'
                    }
                ],
                'actions': [
                    {
                        'type': 'set-encryption'
                    }
                ]
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        sns = session_factory().client('sns')
        attributes = sns.get_topic_attributes(TopicArn=topic)
        self.assertTrue(attributes['Attributes']['KmsMasterKeyId'], 'alias/aws/sns')

    def test_sns_disable_encryption(self):
        session_factory = self.replay_flight_data('test_sns_unset_encryption')
        topic = 'arn:aws:sns:us-west-1:644160558196:test'
        p = self.load_policy(
            {
                'name': 'test-sns-kms-related-filter',
                'resource': 'sns',
                'filters': [
                    {
                        'TopicArn': topic
                    },
                    {
                        'KmsMasterKeyId': 'alias/aws/sns'
                    }
                ],
                'actions': [
                    {
                        'type': 'set-encryption',
                        'enabled': False
                    }
                ]
            },
            session_factory=session_factory
        )

        resources = p.run()

        self.assertEqual(len(resources), 1)

        sns = session_factory().client('sns')
        attributes = sns.get_topic_attributes(TopicArn=topic)['Attributes']
        self.assertFalse(attributes.get('KmsMasterKeyId'))

    def test_sns_set_encryption_custom_key(self):
        session_factory = self.replay_flight_data('test_sns_set_encryption_custom_key')
        topic = 'arn:aws:sns:us-west-1:644160558196:test'
        key_alias = 'alias/alias/test/key'
        sns = session_factory().client('sns')
        p = self.load_policy(
            {
                'name': 'test-sns-kms-related-filter-alias',
                'resource': 'sns',
                'filters': [
                    {
                        'TopicArn': topic
                    },
                    {
                        'KmsMasterKeyId': 'absent'
                    }
                ],
                'actions': [
                    {
                        'type': 'set-encryption',
                        'key': key_alias
                    }
                ]
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        attributes = sns.get_topic_attributes(TopicArn=topic)['Attributes']
        self.assertEqual(attributes.get('KmsMasterKeyId'), key_alias)

    def test_sns_delete(self):
        session_factory = self.replay_flight_data('test_sns_delete_topic')
        policy = """
        name: delete-sns
        resource: aws.sns
        filters:
          - TopicArn: arn:aws:sns:us-west-1:644160558196:test
        actions:
          - type: delete
        """
        p = self.load_policy(yaml_load(policy), session_factory=session_factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
        client = session_factory().client('sns')
        resources = client.list_topics()['Topics']
        self.assertEqual(len(resources), 0)

    def test_sns_tag(self):
        session_factory = self.replay_flight_data("test_sns_tag")
        p = self.load_policy(
            {
                "name": "tag-sns",
                "resource": "sns",
                "filters": [{"tag:Tagging": "absent"}],
                "actions": [{"type": "tag", "key": "Tagging", "value": "added"}],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

        client = session_factory().client("sns")
        tags = client.list_tags_for_resource(ResourceArn=resources[0]["TopicArn"])["Tags"]
        self.assertEqual(tags[0]["Value"], "added")

    def test_sns_remove_tag(self):
        session_factory = self.replay_flight_data(
            "test_sns_remove_tag")
        p = self.load_policy(
            {
                "name": "untag-sns",
                "resource": "sns",
                "filters": [
                    {
                        "type": "marked-for-op",
                        "tag": "custodian_cleanup",
                        "op": "delete",
                    }
                ],
                "actions": [{"type": "remove-tag", "tags": ["custodian_cleanup"]}],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

        client = session_factory().client("sns")
        tags = client.list_tags_for_resource(ResourceArn=resources[0]["TopicArn"])["Tags"]
        self.assertEqual(len(tags), 0)

    def test_sns_mark_for_op(self):
        session_factory = self.replay_flight_data(
            "test_sns_mark_for_op"
        )
        p = self.load_policy(
            {
                "name": "sns-untagged-delete",
                "resource": "sns",
                "filters": [
                    {"tag:Tagging": "absent"},
                    {"tag:custodian_cleanup": "absent"},
                ],
                "actions": [
                    {
                        "type": "mark-for-op",
                        "tag": "custodian_cleanup",
                        "op": "delete",
                        "days": 1,
                    }
                ],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        client = session_factory().client("sns")
        tags = client.list_tags_for_resource(ResourceArn=resources[0]["TopicArn"])["Tags"]
        self.assertTrue(tags[0]["Key"], "custodian_cleanup")
