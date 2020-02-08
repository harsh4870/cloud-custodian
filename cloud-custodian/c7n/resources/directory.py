# Copyright 2015-2017 Capital One Services, LLC
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

from c7n.manager import resources
from c7n.query import QueryResourceManager, TypeInfo
from c7n.utils import local_session
from c7n.filters.vpc import SecurityGroupFilter, SubnetFilter, VpcFilter
from c7n.tags import Tag, RemoveTag, universal_augment


@resources.register('directory')
class Directory(QueryResourceManager):

    class resource_type(TypeInfo):
        service = "ds"
        enum_spec = ("describe_directories", "DirectoryDescriptions", None)
        name = "Name"
        id = "DirectoryId"
        filter_name = 'DirectoryIds'
        filter_type = 'list'
        arn_type = "directory"
        permission_augment = ('ds:ListTagsForResource',)

    def augment(self, directories):
        client = local_session(self.session_factory).client('ds')

        def _add_tags(d):
            d['Tags'] = client.list_tags_for_resource(
                ResourceId=d['DirectoryId']).get('Tags', [])
            return d

        return list(map(_add_tags, directories))


@Directory.filter_registry.register('subnet')
class DirectorySubnetFilter(SubnetFilter):

    RelatedIdsExpression = "VpcSettings.SubnetIds"


@Directory.filter_registry.register('security-group')
class DirectorySecurityGroupFilter(SecurityGroupFilter):

    RelatedIdsExpression = "VpcSettings.SecurityGroupId"


@Directory.filter_registry.register('vpc')
class DirectoryVpcFilter(VpcFilter):

    RelatedIdsExpression = "VpcSettings.VpcId"


@Directory.action_registry.register('tag')
class DirectoryTag(Tag):
    """Add tags to a directory

    :example:

        .. code-block:: yaml

            policies:
              - name: tag-directory
                resource: directory
                filters:
                  - "tag:desired-tag": absent
                actions:
                  - type: tag
                    key: desired-tag
                    value: desired-value
    """
    permissions = ('ds:AddTagsToResource',)

    def process_resource_set(self, client, directories, tags):
        for d in directories:
            try:
                client.add_tags_to_resource(
                    ResourceId=d['DirectoryId'], Tags=tags)
            except client.exceptions.EntityDoesNotExistException:
                continue


@Directory.action_registry.register('remove-tag')
class DirectoryRemoveTag(RemoveTag):
    """Remove tags from a directory

    :example:

        .. code-block:: yaml

            policies:
              - name: remove-directory-tag
                resource: directory
                filters:
                  - "tag:desired-tag": present
                actions:
                  - type: remove-tag
                    tags: ["desired-tag"]
    """
    permissions = ('ds:RemoveTagsFromResource',)

    def process_resource_set(self, client, directories, tags):
        for d in directories:
            try:
                client.remove_tags_from_resource(
                    ResourceId=d['DirectoryId'], TagKeys=tags)
            except client.exceptions.EntityDoesNotExistException:
                continue


@resources.register('cloud-directory')
class CloudDirectory(QueryResourceManager):

    class resource_type(TypeInfo):
        service = "clouddirectory"
        enum_spec = ("list_directories", "Directories", {'state': 'ENABLED'})
        arn = id = "DirectoryArn"
        name = "Name"
        arn_type = "directory"
        universal_taggable = object()

    augment = universal_augment
