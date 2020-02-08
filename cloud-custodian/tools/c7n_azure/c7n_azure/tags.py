# Copyright 2018 Capital One Services, LLC
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
import logging

from azure.mgmt.resource.resources.models import GenericResource, ResourceGroupPatchable
from c7n_azure.utils import is_resource_group


class TagHelper:

    log = logging.getLogger('custodian.azure.utils.TagHelper')

    @staticmethod
    def update_resource_tags(tag_action, resource, tags):
        client = tag_action.session.client('azure.mgmt.resource.ResourceManagementClient')

        # resource group type
        if is_resource_group(resource):
            params_patch = ResourceGroupPatchable(
                tags=tags
            )
            client.resource_groups.update(
                resource['name'],
                params_patch,
            )
        # other Azure resources
        else:
            # deserialize the original object
            az_resource = GenericResource.deserialize(resource)

            if not tag_action.manager.tag_operation_enabled(az_resource.type):
                raise NotImplementedError('Cannot tag resource with type {0}'
                                          .format(az_resource.type))
            api_version = tag_action.session.resource_api_version(resource['id'])

            # create a PATCH object with only updates to tags
            tags_patch = GenericResource(tags=tags)

            client.resources.update_by_id(resource['id'], api_version, tags_patch)

    @staticmethod
    def remove_tags(tag_action, resource, tags_to_delete):
        # get existing tags
        tags = resource.get('tags', {})

        # only determine if any tags_to_delete exist on the resource
        tags_exist = False
        for tag in tags_to_delete:
            if tag in tags:
                tags_exist = True
                break

        # only call the resource update if there are tags to delete tags
        if tags_exist:
            resource_tags = {key: tags[key] for key in tags if key not in tags_to_delete}
            TagHelper.update_resource_tags(tag_action, resource, resource_tags)

    @staticmethod
    def add_tags(tag_action, resource, tags_to_add):
        new_or_updated_tags = False

        # get existing tags
        tags = resource.get('tags', {})

        # add or update tags
        for key in tags_to_add:
            # nothing to do if the tag and value already exists on the resource
            if key in tags:
                if tags[key] != tags_to_add[key]:
                    new_or_updated_tags = True
            else:
                # the tag doesn't exist or the value was updated
                new_or_updated_tags = True

            tags[key] = tags_to_add[key]

        # call the arm resource update method if there are new or updated tags
        if new_or_updated_tags:
            TagHelper.update_resource_tags(tag_action, resource, tags)

    @staticmethod
    def get_tag_value(resource, tag, utf_8=False):
        """Get the resource's tag value."""

        tags = {k.lower(): v for k, v in resource.get('tags', {}).items()}
        value = tags.get(tag, False)

        if value is not False:
            if utf_8:
                value = value.encode('utf8').decode('utf8')
        return value
