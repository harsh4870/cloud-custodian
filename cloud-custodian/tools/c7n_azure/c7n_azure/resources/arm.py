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

import six
from c7n_azure.actions.delete import DeleteAction
from c7n_azure.actions.lock import LockAction
from c7n_azure.actions.tagging import (AutoTagDate)
from c7n_azure.actions.tagging import Tag, AutoTagUser, RemoveTag, TagTrim, TagDelayedAction
from c7n_azure.filters import (CostFilter, MetricFilter, TagActionFilter,
                               DiagnosticSettingsFilter, PolicyCompliantFilter, ResourceLockFilter,
                               AzureOffHour, AzureOnHour)
from c7n_azure.provider import resources
from c7n_azure.query import QueryResourceManager, QueryMeta, ChildResourceManager, TypeInfo, \
    ChildTypeInfo, TypeMeta
from c7n_azure.utils import ResourceIdParser

arm_resource_types = {}


@six.add_metaclass(TypeMeta)
class ArmTypeInfo(TypeInfo):
    # api client construction information for ARM resources
    id = 'id'
    name = 'name'
    diagnostic_settings_enabled = True
    default_report_fields = (
        'name',
        'location',
        'resourceGroup'
    )
    resource_type = None
    enable_tag_operations = True


@six.add_metaclass(QueryMeta)
class ArmResourceManager(QueryResourceManager):
    class resource_type(ArmTypeInfo):
        service = 'azure.mgmt.resource'
        client = 'ResourceManagementClient'
        enum_spec = ('resources', 'list', None)

    def augment(self, resources):
        for resource in resources:
            if 'id' in resource:
                resource['resourceGroup'] = ResourceIdParser.get_resource_group(resource['id'])
        return resources

    def get_resources(self, resource_ids):
        resource_client = self.get_client('azure.mgmt.resource.ResourceManagementClient')
        data = [
            resource_client.resources.get_by_id(rid, self._session.resource_api_version(rid))
            for rid in resource_ids
        ]
        return self.augment([r.serialize(True) for r in data])

    def tag_operation_enabled(self, resource_type):
        return self.resource_type.enable_tag_operations

    @staticmethod
    def register_arm_specific(registry, resource_class):

        if not issubclass(resource_class, ArmResourceManager):
            return

        arm_resource_types[
            resource_class.resource_type.resource_type.lower()] = resource_class.resource_type

        if resource_class.resource_type.enable_tag_operations:
            resource_class.action_registry.register('tag', Tag)
            resource_class.action_registry.register('untag', RemoveTag)
            resource_class.action_registry.register('auto-tag-user', AutoTagUser)
            resource_class.action_registry.register('auto-tag-date', AutoTagDate)
            resource_class.action_registry.register('tag-trim', TagTrim)
            resource_class.filter_registry.register('marked-for-op', TagActionFilter)
            resource_class.action_registry.register('mark-for-op', TagDelayedAction)

        if resource_class.type != 'armresource':
            resource_class.filter_registry.register('cost', CostFilter)

        resource_class.filter_registry.register('metric', MetricFilter)
        resource_class.filter_registry.register('policy-compliant', PolicyCompliantFilter)
        resource_class.filter_registry.register('resource-lock', ResourceLockFilter)
        resource_class.action_registry.register('lock', LockAction)
        resource_class.filter_registry.register('offhour', AzureOffHour)
        resource_class.filter_registry.register('onhour', AzureOnHour)

        resource_class.action_registry.register('delete', DeleteAction)

        if resource_class.resource_type.diagnostic_settings_enabled:
            resource_class.filter_registry.register('diagnostic-settings', DiagnosticSettingsFilter)


@six.add_metaclass(QueryMeta)
class ChildArmResourceManager(ChildResourceManager, ArmResourceManager):

    class resource_type(ChildTypeInfo, ArmTypeInfo):
        pass


resources.subscribe(ArmResourceManager.register_arm_specific)
