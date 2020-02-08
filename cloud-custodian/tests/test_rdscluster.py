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

from c7n.executor import MainThreadExecutor
from c7n.resources.rdscluster import RDSCluster, _run_cluster_method

from .common import BaseTest


class RDSClusterTest(BaseTest):

    def remove_augments(self):
        # This exists because we added tag augmentation after eight other tests
        # were created and I did not want to re-create the state to re-record
        # them with the extra API call. If those get re-recorded we can remove
        # this. -scotwk
        self.patch(RDSCluster, "augment", lambda x, y: y)

    def test_rdscluster_security_group(self):
        self.remove_augments()
        session_factory = self.replay_flight_data("test_rdscluster_sg_filter")
        p = self.load_policy(
            {
                "name": "rdscluster-sg",
                "resource": "rds-cluster",
                "filters": [
                    {"type": "security-group", "key": "GroupName", "value": "default"}
                ],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["DatabaseName"], "devtest")

    def test_rdscluster_subnet(self):
        self.remove_augments()
        session_factory = self.replay_flight_data("test_rdscluster_subnet")
        p = self.load_policy(
            {
                "name": "rdscluster-sub",
                "resource": "rds-cluster",
                "filters": [
                    {"type": "subnet", "key": "MapPublicIpOnLaunch", "value": True}
                ],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["DatabaseName"], "devtest")

    def test_rdscluster_simple(self):
        self.remove_augments()
        session_factory = self.replay_flight_data("test_rdscluster_simple")
        p = self.load_policy(
            {"name": "rdscluster-simple", "resource": "rds-cluster"},
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 2)

    def test_rdscluster_simple_filter(self):
        self.remove_augments()
        session_factory = self.replay_flight_data("test_rdscluster_simple")
        p = self.load_policy(
            {
                "name": "rdscluster-simple-filter",
                "resource": "rds-cluster",
                "filters": [
                    {"type": "value", "key": "DBClusterIdentifier", "value": "bbb"}
                ],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_rdscluster_delete(self):
        self.remove_augments()
        session_factory = self.replay_flight_data("test_rdscluster_delete")
        p = self.load_policy(
            {
                "name": "rdscluster-delete",
                "resource": "rds-cluster",
                "filters": [
                    {"type": "value", "key": "DBClusterIdentifier", "value": "bbb"}
                ],
                "actions": [{"type": "delete", "delete-instances": False}],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_rdscluster_delete_with_instances(self):
        self.remove_augments()
        session_factory = self.replay_flight_data(
            "test_rdscluster_delete_with_instances"
        )
        p = self.load_policy(
            {
                "name": "rdscluster-delete",
                "resource": "rds-cluster",
                "filters": [
                    {"type": "value", "key": "DBClusterIdentifier", "value": "bbb"}
                ],
                "actions": [{"type": "delete", "delete-instances": True}],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_rdscluster_retention(self):
        self.remove_augments()
        session_factory = self.replay_flight_data("test_rdscluster_retention")
        p = self.load_policy(
            {
                "name": "rdscluster-delete",
                "resource": "rds-cluster",
                "filters": [
                    {"type": "value", "key": "DBClusterIdentifier", "value": "bbb"}
                ],
                "actions": [{"type": "retention", "days": 21}],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_rdscluster_snapshot(self):
        self.remove_augments()
        session_factory = self.replay_flight_data("test_rdscluster_snapshot")
        p = self.load_policy(
            {
                "name": "rdscluster-snapshot",
                "resource": "rds-cluster",
                "filters": [
                    {"type": "value", "key": "DBClusterIdentifier", "value": "bbb"}
                ],
                "actions": [{"type": "snapshot"}],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_modify_rds_cluster(self):
        session_factory = self.replay_flight_data("test_modify_rds_cluster")
        p = self.load_policy(
            {
                "name": "modify-db-cluster",
                "resource": "rds-cluster",
                "filters": [{"DeletionProtection": True}],
                "actions": [{
                    "type": "modify-db-cluster",
                    "attributes": {
                        "DeletionProtection": False}
                }]
            },
            session_factory=session_factory, config={'account_id': '644160558196'}
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

        client = session_factory().client("rds")
        cluster = client.describe_db_clusters(
            DBClusterIdentifier='mytest')
        self.assertFalse(cluster['DBClusters'][0]['DeletionProtection'])

    def test_rdscluster_tag_augment(self):
        session_factory = self.replay_flight_data("test_rdscluster_tag_augment")
        p = self.load_policy(
            {
                "name": "rdscluster-tag-augment",
                "resource": "rds-cluster",
                "filters": [{"tag:cfoo": "cbar"}],
            },
            session_factory=session_factory,
        )

        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_rdscluster_tag_and_remove(self):
        self.patch(RDSCluster, "executor_factory", MainThreadExecutor)
        session_factory = self.replay_flight_data("test_rdscluster_tag_and_remove")
        client = session_factory().client("rds")

        p = self.load_policy(
            {
                "name": "rds-cluster-tag",
                "resource": "rds-cluster",
                "filters": [{"DBClusterIdentifier": "c7ntest"}],
                "actions": [{"type": "tag", "key": "xyz", "value": "hello world"}],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

        arn = p.resource_manager.generate_arn(resources[0]["DBClusterIdentifier"])

        tags = client.list_tags_for_resource(ResourceName=arn)
        tag_map = {t["Key"]: t["Value"] for t in tags["TagList"]}
        self.assertTrue("xyz" in tag_map)

        policy = self.load_policy(
            {
                "name": "rds-cluster-remove-tag",
                "resource": "rds-cluster",
                "filters": [{"tag:xyz": "not-null"}],
                "actions": [{"type": "remove-tag", "tags": ["xyz"]}],
            },
            session_factory=session_factory,
        )
        resources = policy.run()
        self.assertEqual(len(resources), 1)

        tags = client.list_tags_for_resource(ResourceName=arn)
        tag_map = {t["Key"]: t["Value"] for t in tags["TagList"]}
        self.assertFalse("xyz" in tag_map)

    def test_rdscluster_mark_match_unmark(self):
        session_factory = self.replay_flight_data("test_rdscluster_mark_and_match")
        client = session_factory().client("rds")

        # mark
        p = self.load_policy(
            {
                "name": "rds-mark",
                "resource": "rds-cluster",
                "filters": [{"DBClusterIdentifier": "c7ntest"}],
                "actions": [
                    {
                        "type": "mark-for-op",
                        "tag": "custodian_next",
                        "days": 1,
                        "op": "delete",
                    }
                ],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

        # assert marked
        arn = p.resource_manager.generate_arn(resources[0]["DBClusterIdentifier"])
        tags = client.list_tags_for_resource(ResourceName=arn)
        tag_map = {t["Key"]: t["Value"] for t in tags["TagList"]}
        self.assertTrue("custodian_next" in tag_map)

        # match marked
        policy = self.load_policy(
            {
                "name": "rds-mark-filter",
                "resource": "rds-cluster",
                "filters": [
                    {
                        "type": "marked-for-op",
                        "tag": "custodian_next",
                        "op": "delete",
                        "skew": 1,
                    }
                ],
            },
            session_factory=session_factory,
        )
        resources = policy.run()
        self.assertEqual(len(resources), 1)

        # unmark
        policy = self.load_policy(
            {
                "name": "rds-mark-filter",
                "resource": "rds-cluster",
                "filters": [
                    {
                        "type": "marked-for-op",
                        "tag": "custodian_next",
                        "op": "delete",
                        "skew": 1,
                    }
                ],
                "actions": [{"type": "unmark", "tags": ["custodian_next"]}],
            },
            session_factory=session_factory,
        )
        resources = policy.run()
        self.assertEqual(len(resources), 1)

        # assert unmarked
        tags = client.list_tags_for_resource(ResourceName=arn)
        tag_map = {t["Key"]: t["Value"] for t in tags["TagList"]}
        self.assertFalse("custodian_next" in tag_map)

    def test_run_cluster_method(self):

        output = self.capture_logging('custodian.rds-cluster')

        def foobar(DBClusterIdentifier):
            raise ValueError("eek")

        # unspecified
        self.assertRaises(
            ValueError, _run_cluster_method, foobar, {'DBClusterIdentifier': 'mytest'})

        # ignored
        try:
            _run_cluster_method(foobar, {'DBClusterIdentifier': 'mytest'}, ValueError)
        except ValueError:
            self.fail("Shouldn't raise")
        finally:
            self.assertEqual(output.getvalue(), "")

        # warn
        try:
            _run_cluster_method(
                foobar, {'DBClusterIdentifier': 'mytest'}, warn=(ValueError, KeyError))
        except ValueError:
            self.fail("Shouldn't raise")
        finally:
            self.assertTrue("eek" in output.getvalue())

    def test_stop(self):
        factory = self.replay_flight_data("test_rdscluster_stop")
        p = self.load_policy(
            {"name": "rdscluster",
             "resource": "rds-cluster",
             "filters": [{'DBClusterIdentifier': 'mytest'}],
             'actions': ['stop']},
            session_factory=factory, config={'account_id': '644160558196'})
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['Status'], 'available')

        client = factory().client('rds')
        cluster = client.describe_db_clusters(
            DBClusterIdentifier='mytest').get('DBClusters')[0]
        self.assertEqual(cluster['Status'], 'stopping')

    def test_start(self):
        factory = self.replay_flight_data("test_rdscluster_start")
        p = self.load_policy(
            {"name": "rdscluster",
             "resource": "rds-cluster",
             "filters": [{'DBClusterIdentifier': 'mytest'}],
             'actions': ['start']},
            session_factory=factory, config={'account_id': '644160558196'})
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['Status'], 'stopped')

        client = factory().client('rds')
        cluster = client.describe_db_clusters(
            DBClusterIdentifier='mytest').get('DBClusters')[0]
        self.assertEqual(cluster['Status'], 'starting')


class RDSClusterSnapshotTest(BaseTest):

    def test_rdscluster_snapshot_simple(self):
        session_factory = self.replay_flight_data("test_rdscluster_snapshot_simple")
        p = self.load_policy(
            {"name": "rdscluster-snapshot-simple", "resource": "rds-cluster-snapshot"},
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 2)

    def test_rdscluster_snapshot_simple_filter(self):
        session_factory = self.replay_flight_data("test_rdscluster_snapshot_simple")
        p = self.load_policy(
            {
                "name": "rdscluster-snapshot-simple-filter",
                "resource": "rds-cluster-snapshot",
                "filters": [
                    {"type": "value", "key": "StorageEncrypted", "value": False}
                ],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_rdscluster_snapshot_age_filter(self):
        factory = self.replay_flight_data("test_rdscluster_snapshot_simple")
        p = self.load_policy(
            {
                "name": "rdscluster-snapshot-age-filter",
                "resource": "rds-cluster-snapshot",
                "filters": [{"type": "age", "days": 7}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 2)

    def test_rdscluster_snapshot_trim(self):
        factory = self.replay_flight_data("test_rdscluster_snapshot_delete")
        p = self.load_policy(
            {
                "name": "rdscluster-snapshot-trim",
                "resource": "rds-cluster-snapshot",
                "actions": ["delete"],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 2)
