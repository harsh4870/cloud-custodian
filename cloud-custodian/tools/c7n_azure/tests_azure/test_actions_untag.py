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
from .azure_common import BaseTest
from c7n_azure.actions.tagging import RemoveTag
from mock import patch, Mock

from c7n.filters import FilterValidationError


class ActionsRemoveTagTest(BaseTest):

    existing_tags = {'pre-existing-1': 'unmodified', 'pre-existing-2': 'unmodified'}

    def _get_action(self, data):
        return RemoveTag(data=data, manager=Mock())

    def test_schema_validate(self):
        self.assertTrue(
            self.load_policy(
                tools.get_policy([
                    {'type': 'untag',
                     'tags': ['test']}
                ])))

        with self.assertRaises(FilterValidationError):
            # Must specify tags to remove
            self.load_policy(tools.get_policy([
                {'type': 'untag'}
            ]))

    @patch('c7n_azure.tags.TagHelper.update_resource_tags')
    def test_remove_single_tag(self, update_resource_tags):
        """Verifies we can delete a tag without modifying an existing tag on that resource
        """

        action = self._get_action({'tags': ['tag-to-delete']})

        tags = self.existing_tags.copy()
        tags.update({'tag-to-delete': 'value'})

        resource = tools.get_resource(tags)

        action.process([resource])

        tags = tools.get_tags_parameter(update_resource_tags)

        self.assertEqual(tags, self.existing_tags)

    @patch('c7n_azure.tags.TagHelper.update_resource_tags')
    def test_remove_tags(self, update_resource_tags):
        """Verifies we can delete multiple tags without modifying existing tags.
        """

        action = self._get_action({'tags': ['tag-to-delete-1', 'tag-to-delete-2']})

        tags = self.existing_tags.copy()
        tags.update({'tag-to-delete-1': 'value1', 'tag-to-delete-2': 'value2'})

        resource = tools.get_resource(tags)

        action.process([resource])

        tags = tools.get_tags_parameter(update_resource_tags)

        self.assertEqual(tags, self.existing_tags)

    @patch('c7n_azure.tags.TagHelper.update_resource_tags')
    def test_removal_works_with_nonexistent_tag(self, update_resource_tags):
        """Verifies attempting to delete a tag that is not on the resource does not throw an error
        """

        action = self._get_action({'tags': ['tag-does-not-exist']})

        tags = self.existing_tags.copy()

        resource = tools.get_resource(tags)

        action.process([resource])

        update_resource_tags.assert_not_called()
