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

import re

from . import tools_tags as tools
from .azure_common import BaseTest
from c7n_azure.actions.tagging import TagTrim
from mock import patch, Mock

from c7n.filters import FilterValidationError


class TagsTest(BaseTest):

    existing_tags = {'pre-existing-1': 'unmodified', 'pre-existing-2': 'unmodified'}

    def _get_action(self, data):
        return TagTrim(data=data, manager=Mock())

    def test_schema_validate(self):
        self.assertTrue(
            self.load_policy(
                tools.get_policy([
                    {'type': 'tag-trim',
                     'space': 5},
                ]),
                validate=True))

        with self.assertRaises(FilterValidationError):
            # Space must be btwn 0 and 15
            self.load_policy(tools.get_policy([
                {'type': 'tag-trim',
                 'space': -1}
            ]))

        with self.assertRaises(FilterValidationError):
            # Space must be btwn 0 and 15
            self.load_policy(tools.get_policy([
                {'type': 'tag-trim',
                 'space': 16}
            ]))

    @patch('c7n_azure.tags.TagHelper.update_resource_tags')
    def test_tag_trim_does_nothing_if_space_available(self, update_resource_tags):
        """Verifies tag trim returns without trimming tags
        if the resource has space equal to or greater than
        the space value.
        """

        action = self._get_action({'space': 1})
        resource = tools.get_resource(self.existing_tags)

        action.process([resource])
        update_resource_tags.assert_not_called()

    @patch('c7n_azure.tags.TagHelper.update_resource_tags')
    def test_tag_trim_removes_tags_for_space(self, update_resource_tags):
        """Verifies tag trim removes tags when the space value
        and number of tags on the resource are greater than the max
        tag value (15)
        """

        action = self._get_action({'space': 15 - len(self.existing_tags),
                                   'preserve': [k for k in self.existing_tags.keys()]})

        tags = self.existing_tags.copy()
        tags.update({'tag-to-trim1': 'value1', 'tag-to-trim2': 'value2'})
        resource = tools.get_resource(tags)

        action.process([resource])

        tags = tools.get_tags_parameter(update_resource_tags)

        expected_tags = self.existing_tags.copy()

        self.assertEqual(tags, expected_tags)

    @patch('c7n_azure.tags.TagHelper.update_resource_tags')
    def test_tag_trim_space_0_removes_all_tags_but_preserve(self, update_resource_tags):
        """Verifies tag trim removes all other tags but tags listed in preserve
        """

        action = self._get_action({'space': 0,
                                   'preserve': [k for k in self.existing_tags.keys()]})

        tags = self.existing_tags.copy()
        tags.update({'tag-to-trim1': 'value1', 'tag-to-trim2': 'value2', 'tag-to-trim-3': 'value3'})
        resource = tools.get_resource(tags)

        action.process([resource])

        tags = tools.get_tags_parameter(update_resource_tags)

        expected_tags = self.existing_tags.copy()

        self.assertEqual(tags, expected_tags)

    @patch('c7n_azure.tags.TagHelper.update_resource_tags')
    @patch('logging.Logger.warning')
    def test_tag_trim_warns_no_candidates(self, logger_mock, update_resource_tags):
        """Verifies tag trim warns when there are no candidates to trim
        """

        action = self._get_action({'space': 0,
                                   'preserve': [k for k in self.existing_tags.keys()]})

        tags = self.existing_tags.copy()
        resource = tools.get_resource(tags)

        action.process([resource])

        update_resource_tags.assert_not_called()

        expected_warning_regex = (
            "Could not find any candidates to trim "
            "/subscriptions/[^/]+/resourceGroups/[^/]+/"
            "providers/Microsoft.Compute/virtualMachines/[^/]+"
        )

        args, _ = logger_mock.call_args
        self.assertTrue(re.match(expected_warning_regex, args[0]) is not None)
