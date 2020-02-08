# Copyright 2015-2018 Capital One Services, LLC
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

from ..azure_common import BaseTest, arm_template


class WebAppTest(BaseTest):
    def setUp(self):
        super(WebAppTest, self).setUp()

    def test_validate_webapp_schema(self):
        with self.sign_out_patch():

            p = self.load_policy({
                'name': 'test-azure-webapp',
                'resource': 'azure.webapp'
            }, validate=True)

            self.assertTrue(p)

    @arm_template('webapp.json')
    def test_find_by_name(self):
        p = self.load_policy({
            'name': 'test-azure-webapp',
            'resource': 'azure.webapp',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctestwebapp*'}],
        })
        resources = p.run()
        self.assertEqual(len(resources), 1)

    @arm_template('webapp.json')
    def test_find_by_min_tls(self):
        # webapp.json deploys a webapp with minTlsVerion='1.0'
        p = self.load_policy({
            'name': 'test-azure-webapp',
            'resource': 'azure.webapp',
            'filters': [
                {
                    'type': 'value',
                    'key': 'name',
                    'op': 'glob',
                    'value_type': 'normalize',
                    'value': 'cctestwebapp*'},
                {
                    'type': 'configuration',
                    'key': 'minTlsVersion',
                    'value': '1.2',
                    'op': 'ne'
                }
            ]
        })
        resources = p.run()
        self.assertEqual(len(resources), 1)
