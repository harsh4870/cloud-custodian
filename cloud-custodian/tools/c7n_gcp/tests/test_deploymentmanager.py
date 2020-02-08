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
import time

from gcp_common import BaseTest


class DMDeploymentTest(BaseTest):
    def test_deployment_query(self):
        project_id = 'mitraject'
        session_factory = self.replay_flight_data('dm-deployment-query', project_id=project_id)

        policy = {
            'name': 'all-deployments',
            'resource': 'gcp.dm-deployment'
        }

        policy = self.load_policy(
            policy,
            session_factory=session_factory)

        resources = policy.run()
        self.assertEqual(resources[0]['name'], 'mydep2')

    def test_deployment_get(self):
        project_id = 'mitraject'
        session_factory = self.replay_flight_data('dm-deployment-get', project_id=project_id)

        policy = {
            'name': 'one-deployment',
            'resource': 'gcp.dm-deployment'
        }

        policy = self.load_policy(
            policy,
            session_factory=session_factory)

        deployment = policy.resource_manager.get_resource({
            'project_id': project_id,
            'name': 'mydep2'
        })

        self.assertEqual(deployment['id'], '7713223424225049872')

    def test_deployment_delete(self):
        project_id = 'mitrop-custodian'
        factory = self.replay_flight_data('dm-deployment-delete', project_id=project_id)

        p = self.load_policy(
            {'name': 'delete-deployment',
             'resource': 'gcp.dm-deployment',
             'filters': [{'name': 'lamp-1'}],
             'actions': ['delete']},
            session_factory=factory)

        resources = p.run()
        self.assertEqual(len(resources), 1)

        if self.recording:
            time.sleep(3)

        client = p.resource_manager.get_client()
        result = client.execute_query(
            'list', {'project': project_id,
                     'filter': 'name = lamp-1'})

        self.assertEqual(result['deployments'][0]['operation']['operationType'], 'delete')
