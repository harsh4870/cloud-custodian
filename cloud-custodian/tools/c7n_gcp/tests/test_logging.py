# Copyright 2019 Capital One Services, LLC
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

from gcp_common import BaseTest, event_data


class LogProjectSinkTest(BaseTest):

    def test_query(self):
        project_id = 'cloud-custodian'
        factory = self.replay_flight_data('log-project-sink-query', project_id)
        p = self.load_policy({
            'name': 'log-project-sink',
            'resource': 'gcp.log-project-sink'},
            session_factory=factory)
        resource = p.run()
        self.assertEqual(len(resource), 1)

    def test_get_project_sink(self):
        project_id = 'cloud-custodian'
        sink_name = "testqqqqqqqqqqqqqqqqq"
        factory = self.replay_flight_data(
            'log-project-sink-resource', project_id)
        p = self.load_policy({'name': 'log-project-sink-resource',
                              'resource': 'gcp.log-project-sink',
                              'mode': {
                                  'type': 'gcp-audit',
                                  'methods': ['google.logging.v2.ConfigServiceV2.CreateSink']}
                              },
                             session_factory=factory)

        exec_mode = p.get_execution_mode()
        event = event_data('log-create-project-sink.json')
        resource = exec_mode.run(event, None)
        self.assertEqual(resource[0]['name'], sink_name)


class LogSinkTest(BaseTest):

    def test_query(self):
        project_id = 'cloud-custodian'
        factory = self.replay_flight_data('logsink', project_id)
        p = self.load_policy({
            'name': 'logsink',
            'resource': 'gcp.logsink'},
            session_factory=factory)
        resource = p.run()
        self.assertEqual(len(resource), 1)

    def test_get_log_sink(self):
        project_id = 'cloud-custodian'
        sink_name = "testqqqqqqqqqqqqqqqqq"
        factory = self.replay_flight_data(
            'log-project-sink-resource', project_id)
        p = self.load_policy({'name': 'logsink',
                              'resource': 'gcp.logsink',
                              'mode': {
                                  'type': 'gcp-audit',
                                  'methods': ['google.logging.v2.ConfigServiceV2.CreateSink']}
                              },
                             session_factory=factory)

        exec_mode = p.get_execution_mode()
        event = event_data('log-create-project-sink.json')
        resource = exec_mode.run(event, None)
        self.assertEqual(resource[0]['name'], sink_name)


class LogProjectMetricTest(BaseTest):

    def test_query(self):
        project_id = 'cloud-custodian'
        factory = self.replay_flight_data('log-project-metric-get', project_id)
        p = self.load_policy({
            'name': 'log-project-metric',
            'resource': 'gcp.log-project-metric'},
            session_factory=factory)
        resource = p.run()
        self.assertEqual(len(resource), 1)

    def test_get_project_metric(self):
        project_id = 'cloud-custodian'
        metric_name = "test_name"
        factory = self.replay_flight_data(
            'log-project-metric-query', project_id)
        p = self.load_policy({'name': 'log-project-metric',
                              'resource': 'gcp.log-project-metric',
                              'mode': {
                                  'type': 'gcp-audit',
                                  'methods': ['google.logging.v2.MetricsServiceV2.CreateLogMetric']}
                              },
                             session_factory=factory)

        exec_mode = p.get_execution_mode()
        event = event_data('log-create-project-metric.json')
        resource = exec_mode.run(event, None)
        self.assertEqual(resource[0]['name'], metric_name)


class LogExclusionTest(BaseTest):

    def test_query(self):
        project_id = 'cloud-custodian'
        factory = self.replay_flight_data('log-exclusion', project_id)
        p = self.load_policy({
            'name': 'log-exclusion',
            'resource': 'gcp.log-exclusion'},
            session_factory=factory)
        resource = p.run()
        self.assertEqual(len(resource), 1)

    def test_get_project_exclusion(self):
        project_id = 'cloud-custodian'
        exclusion_name = "qwerty"
        factory = self.replay_flight_data(
            'log-exclusion-get', project_id)

        p = self.load_policy({'name': 'log-exclusion-get',
                              'resource': 'gcp.log-exclusion',
                              'mode': {
                                  'type': 'gcp-audit',
                                  'methods': ['google.logging.v2.ConfigServiceV2.CreateExclusion']}
                              },
                             session_factory=factory)

        exec_mode = p.get_execution_mode()
        event = event_data('log-create-project-exclusion.json')
        resource = exec_mode.run(event, None)
        self.assertEqual(resource[0]['name'], exclusion_name)
