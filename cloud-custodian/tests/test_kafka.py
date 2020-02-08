import time

from .common import BaseTest


class KafkaTest(BaseTest):

    def test_subnet_filter(self):
        factory = self.replay_flight_data('test_kafka_subnet_filter')
        p = self.load_policy({
            'name': 'kafka',
            'resource': 'aws.kafka',
            'filters': [
                {'type': 'subnet',
                 'key': 'tag:NetworkLocation',
                 'value': 'Public'}]},
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_delete(self):
        factory = self.replay_flight_data('test_kafka_delete')
        p = self.load_policy({
            'name': 'kafka',
            'resource': 'aws.kafka',
            'filters': [
                {'ClusterName': 'dev'}],
            'actions': [
                {'type': 'delete'},
            ]},
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)

        if self.recording:
            time.sleep(5)

        client = factory().client('kafka')
        cluster = client.describe_cluster(ClusterArn=resources[0]['ClusterArn']).get('ClusterInfo')
        self.assertEqual(cluster['State'], 'DELETING')
