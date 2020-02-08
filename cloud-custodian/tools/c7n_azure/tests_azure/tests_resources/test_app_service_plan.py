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

from azure.mgmt.web import WebSiteManagementClient
from ..azure_common import BaseTest, arm_template, cassette_name
from c7n_azure.session import Session
from mock import patch

from c7n.exceptions import PolicyValidationError
from c7n.utils import local_session


class AppServicePlanTest(BaseTest):

    def setUp(self):
        super(AppServicePlanTest, self).setUp()
        self.session = local_session(Session)
        self.client = local_session(Session).client(
            'azure.mgmt.web.WebSiteManagementClient')  # type: WebSiteManagementClient
        self.update_mock_path =\
            'azure.mgmt.web.v{}.operations._app_service_plans_operations.' \
            'AppServicePlansOperations.update'\
            .format(self.client._get_api_version('app_service_plans').replace('-', '_'))

    def test_app_service_plan_schema_validate(self):
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'test-azure-appserviceplan-win',
                'resource': 'azure.appserviceplan',
                'filters': [
                    {'type': 'offhour',
                     'default_tz': "pt",
                     'offhour': 18,
                     'tag': 'schedule'},
                    {'type': 'onhour',
                     'default_tz': "pt",
                     'onhour': 18,
                     'tag': 'schedule'}],
                'actions': [
                    {'type': 'resize-plan',
                     'size': 'F1'}],
            }, validate=True)
            self.assertTrue(p)

        # size and count are missing
        with self.assertRaises(PolicyValidationError):
            self.load_policy({
                'name': 'test-azure-appserviceplan',
                'resource': 'azure.appserviceplan',
                'actions': [
                    {'type': 'resize-plan'}
                ]
            }, validate=True)

    @arm_template('appserviceplan.json')
    @cassette_name('window_plans')
    def test_resize_plan_win(self):
        with patch(self.update_mock_path) as update_mock:
            p = self.load_policy({
                'name': 'test-azure-appserviceplan-win',
                'resource': 'azure.appserviceplan',
                'filters': [
                    {'type': 'value',
                     'key': 'name',
                     'op': 'eq',
                     'value_type': 'normalize',
                     'value': 'cctest-appserviceplan-win'},
                    {'type': 'value',
                     'key': 'sku.name',
                     'op': 'eq',
                     'value': 'S1'}
                ],
                'actions': [
                    {'type': 'resize-plan',
                     'size': 'B1',
                     'count': 2}]
            }, validate=True)
            resources = p.run()
            self.assertEqual(1, len(resources))

            name, args, kwargs = update_mock.mock_calls[0]
            self.assertEqual('cctest-appserviceplan-win', args[1])
            self.assertEqual('B1', args[2].sku.name)
            self.assertEqual('BASIC', args[2].sku.tier)
            self.assertEqual(2, args[2].sku.capacity)

    @arm_template('appserviceplan-linux.json')
    @cassette_name('linux_plans')
    def test_resize_plan_linux(self):
        with patch(self.update_mock_path) as update_mock:
            p = self.load_policy({
                'name': 'test-azure-appserviceplan-linux',
                'resource': 'azure.appserviceplan',
                'filters': [
                    {'type': 'value',
                     'key': 'name',
                     'op': 'eq',
                     'value_type': 'normalize',
                     'value': 'cctest-appserviceplan-linux'},
                    {'type': 'value',
                     'key': 'sku.name',
                     'op': 'eq',
                     'value': 'S1'}
                ],
                'actions': [
                    {'type': 'resize-plan',
                     'size': 'B1',
                     'count': 3}]
            }, validate=True)
            resources = p.run()
            self.assertEqual(1, len(resources))

            name, args, kwargs = update_mock.mock_calls[0]
            self.assertEqual('cctest-appserviceplan-linux', args[1])
            self.assertEqual('B1', args[2].sku.name)
            self.assertEqual('BASIC', args[2].sku.tier)
            self.assertEqual(3, args[2].sku.capacity)

    @arm_template('appserviceplan.json')
    @cassette_name('window_plans')
    def test_resize_plan_from_resource_tag(self):
        with patch(self.update_mock_path) as update_mock:
            p = self.load_policy({
                'name': 'test-azure-appserviceplan',
                'resource': 'azure.appserviceplan',
                'filters': [
                    {'type': 'value',
                     'key': 'name',
                     'op': 'eq',
                     'value_type': 'normalize',
                     'value': 'cctest-appserviceplan-win'}],
                'actions': [
                    {'type': 'resize-plan',
                     'size': {
                         'type': 'resource',
                         'key': 'tags.sku'
                     }}],
            })
            resources = p.run()
            self.assertEqual(1, len(resources))

            name, args, kwargs = update_mock.mock_calls[0]
            self.assertEqual('cctest-appserviceplan-win', args[1])
            self.assertEqual('B1', args[2].sku.name)
            self.assertEqual('BASIC', args[2].sku.tier)

    @arm_template('appserviceplan.json')
    @patch('c7n_azure.resources.appserviceplan.ResizePlan.log.info')
    @cassette_name('window_plans')
    def test_resize_consumption_win(self, logger):
        p = self.load_policy({
            'name': 'test-azure-consumption-win',
            'resource': 'azure.appserviceplan',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'eq',
                 'value_type': 'normalize',
                 'value': 'cctest-consumption-win'}
            ],
            'actions': [
                {'type': 'resize-plan',
                 'size': 'F1'}]
        }, validate=True)
        p.run()

        logger.assert_any_call(
            'Skipping cctest-consumption-win, '
            'because this App Service Plan is for Consumption Azure Functions.')

    @arm_template('appserviceplan-linux.json')
    @patch('c7n_azure.resources.appserviceplan.ResizePlan.log.info')
    @cassette_name('linux_plans')
    def test_resize_consumption_linux(self, logger):
        p = self.load_policy({
            'name': 'test-azure-appserviceplan-linux',
            'resource': 'azure.appserviceplan',
            'filters': [
                {'resourceGroup': 'test_appserviceplan-linux'},
                {'type': 'value',
                 'key': 'name',
                 'op': 'ne',
                 'value_type': 'normalize',
                 'value': 'cctest-appserviceplan-linux'}
            ],
            'actions': [
                {'type': 'resize-plan',
                 'size': 'F1'}]
        }, validate=True)
        resources = p.run()

        self.assertEqual(1, len(resources))

        logger.assert_any_call(
            'Skipping {}, because this App Service Plan is for Consumption Azure Functions.'.format(
                resources[0]['name']
            ))

    @arm_template('appserviceplan.json')
    @cassette_name('window_plans')
    def test_resize_plan_win_only_count(self):
        with patch(self.update_mock_path) as update_mock:
            p = self.load_policy({
                'name': 'test-azure-appserviceplan-win',
                'resource': 'azure.appserviceplan',
                'filters': [
                    {'type': 'value',
                     'key': 'name',
                     'op': 'eq',
                     'value_type': 'normalize',
                     'value': 'cctest-appserviceplan-win'},
                    {'type': 'value',
                     'key': 'sku.name',
                     'op': 'eq',
                     'value': 'S1'}
                ],
                'actions': [
                    {'type': 'resize-plan',
                     'count': 3}]
            }, validate=True)
            resources = p.run()
            self.assertEqual(1, len(resources))

            name, args, kwargs = update_mock.mock_calls[0]
            self.assertEqual('cctest-appserviceplan-win', args[1])
            self.assertEqual('S1', args[2].sku.name)
            self.assertEqual('Standard', args[2].sku.tier)
            self.assertEqual(3, args[2].sku.capacity)
