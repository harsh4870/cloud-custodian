# Copyright 2019 Microsoft Corporation
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

from . import tools_tags as tools
from azure.mgmt.monitor.models import EventData
from .azure_common import BaseTest
from c7n_azure.actions.tagging import AutoTagBase, AutoTagDate
from mock import patch, Mock

from c7n.exceptions import PolicyValidationError
from c7n.filters import FilterValidationError


class ActionsAutotagDateTest(BaseTest):

    existing_tags = {'pre-existing-1': 'unmodified', 'pre-existing-2': 'unmodified'}

    vm_id = "/subscriptions/ea42f556-5106-4743-99b0-c129bfa71a47/resourcegroups/" \
            "TEST_VM/providers/Microsoft.Compute/virtualMachines/cctestvm"

    first_event = EventData.from_dict({
        "caller": "cloud@custodian.com",
        "id": vm_id + "/events/37bf930a-fbb8-4c8c-9cc7-057cc1805c04/ticks/636923208048336028",
        "operationName": {
            "value": "Microsoft.Compute/virtualMachines/write",
            "localizedValue": "Create or Update Virtual Machine"
        },
        "eventTimestamp": "2019-05-01T15:20:04.8336028Z"
    })

    def _get_action(self, data):
        return AutoTagDate(data=data, manager=Mock())

    def test_schema_validate(self):
        self.assertTrue(
            self.load_policy(
                tools.get_policy([
                    {'type': 'auto-tag-date',
                     'tag': 'CreatedDate'},
                ]),
                validate=True))

        self.assertTrue(
            self.load_policy(
                tools.get_policy([
                    {'type': 'auto-tag-date',
                     'tag': 'CreatedDate',
                     'format': '%m-%d-%Y'},
                ]),
                validate=True))

        with self.assertRaises(FilterValidationError):
            # Days should be in 1-90 range
            self.load_policy(tools.get_policy([
                {'type': 'auto-tag-date',
                 'tag': 'CreatedDate',
                 'days': 91}
            ]), validate=True)

        with self.assertRaises(FilterValidationError):
            # Days should be in 1-90 range
            self.load_policy(tools.get_policy([
                {'type': 'auto-tag-date',
                 'tag': 'CreatedDate',
                 'days': 0}
            ]), validate=True)

        with self.assertRaises(PolicyValidationError):
            # Event grid mode is incompatible with days
            self.load_policy(tools.get_policy_event_grid([
                {'type': 'auto-tag-date',
                 'tag': 'CreatedDate',
                 'days': 40}
            ]), validate=True)

    @patch.object(AutoTagBase, '_get_first_event', return_value=first_event)
    @patch('c7n_azure.tags.TagHelper.update_resource_tags')
    def test_auto_tag_add_created_date_tag(self, update_resource_tags, _2):
        """Adds CreatorEmail to a resource group."""

        action = self._get_action({'tag': 'CreatedDate', 'days': 10, 'update': True})
        resource = tools.get_resource(self.existing_tags)

        action.process([resource])

        tags = tools.get_tags_parameter(update_resource_tags)

        expected_tags = self.existing_tags.copy()
        expected_tags.update({'CreatedDate': '05.01.2019'})

        self.assertEqual(tags, expected_tags)

    @patch.object(AutoTagBase, '_get_first_event', return_value=first_event)
    @patch('c7n_azure.tags.TagHelper.update_resource_tags')
    def test_auto_tag_add_created_date_tag_custom_format(self, update_resource_tags, _2):
        """Adds CreatorEmail to a resource group."""

        action = self._get_action({'tag': 'CreatedDate', 'format': '%m/%d/%Y'})
        resource = tools.get_resource(self.existing_tags)

        action.process([resource])

        tags = tools.get_tags_parameter(update_resource_tags)

        expected_tags = self.existing_tags.copy()
        expected_tags.update({'CreatedDate': '05/01/2019'})

        self.assertEqual(tags, expected_tags)

    @patch.object(AutoTagBase, '_get_first_event', return_value=first_event)
    @patch('c7n_azure.tags.TagHelper.update_resource_tags')
    def test_auto_tag_update_false_noop_for_existing_tag(self, update_resource_tags, _2):
        """Adds CreatorEmail to a resource group"""

        action = self._get_action({'tag': 'CreatedDate', 'days': 10, 'update': False})

        tags = self.existing_tags.copy()
        tags.update({'CreatedDate': 'do-not-modify'})
        resource = tools.get_resource(tags)

        action.process([resource])

        update_resource_tags.assert_not_called()

    @patch('c7n_azure.tags.TagHelper.update_resource_tags')
    def test_auto_tag_user_event_grid_event(self, update_resource_tags):
        event = {'eventTime': '2019-05-01T15:20:04.8336028Z'}

        action = self._get_action({'tag': 'CreatedDate', 'update': True})

        resource = tools.get_resource(self.existing_tags)
        action.process(resources=[resource], event=event)

        tags = tools.get_tags_parameter(update_resource_tags)

        expected_tags = self.existing_tags.copy()
        expected_tags.update({'CreatedDate': '05.01.2019'})

        self.assertEqual(tags, expected_tags)
