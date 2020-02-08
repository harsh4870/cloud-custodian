# Copyright 2015-2019 Capital One Services, LLC
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

import itertools
import logging

from concurrent.futures import as_completed
import jmespath

from c7n.actions import BaseAction
from c7n.exceptions import ClientError
from c7n.filters import (
    AgeFilter, Filter, CrossAccountAccessFilter)
from c7n.manager import resources
from c7n.query import QueryResourceManager, DescribeSource, TypeInfo
from c7n.resolver import ValuesFrom
from c7n.utils import local_session, type_schema, chunks


log = logging.getLogger('custodian.ami')


@resources.register('ami')
class AMI(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'ec2'
        arn_type = 'image'
        enum_spec = (
            'describe_images', 'Images', None)
        id = 'ImageId'
        filter_name = 'ImageIds'
        filter_type = 'list'
        name = 'Name'
        date = 'CreationDate'

    def resources(self, query=None):
        query = query or {}
        if query.get('Owners') is None:
            query['Owners'] = ['self']
        return super(AMI, self).resources(query=query)

    def get_source(self, source_type):
        if source_type == 'describe':
            return DescribeImageSource(self)
        return super(AMI, self).get_source(source_type)


class DescribeImageSource(DescribeSource):

    def get_resources(self, ids, cache=True):
        while ids:
            try:
                return super(DescribeImageSource, self).get_resources(ids, cache)
            except ClientError as e:
                bad_ami_ids = ErrorHandler.extract_bad_ami(e)
                if bad_ami_ids:
                    for b in bad_ami_ids:
                        ids.remove(b)
                    continue
                raise
        return []


class ErrorHandler(object):

    @staticmethod
    def extract_bad_ami(e):
        """Handle various client side errors when describing images"""
        msg = e.response['Error']['Message']
        error = e.response['Error']['Code']
        e_ami_ids = None
        if error == 'InvalidAMIID.NotFound':
            e_ami_ids = [
                e_ami_id.strip() for e_ami_id
                in msg[msg.find("'[") + 2:msg.rfind("]'")].split(',')]
            log.warning("Image not found %s" % e_ami_ids)
        elif error == 'InvalidAMIID.Malformed':
            e_ami_ids = [msg[msg.find('"') + 1:msg.rfind('"')]]
            log.warning("Image id malformed %s" % e_ami_ids)
        return e_ami_ids


@AMI.action_registry.register('deregister')
class Deregister(BaseAction):
    """Action to deregister AMI

    To prevent deregistering all AMI, it is advised to use in conjunction with
    a filter (such as image-age)

    :example:

    .. code-block:: yaml

            policies:
              - name: ami-deregister-old
                resource: ami
                filters:
                  - type: image-age
                    days: 90
                actions:
                  - deregister
    """

    schema = type_schema('deregister', **{'delete-snapshots': {'type': 'boolean'}})
    permissions = ('ec2:DeregisterImage',)
    snap_expr = jmespath.compile('BlockDeviceMappings[].Ebs.SnapshotId')

    def process(self, images):
        client = local_session(self.manager.session_factory).client('ec2')
        image_count = len(images)
        images = [i for i in images if self.manager.ctx.options.account_id == i['OwnerId']]
        if len(images) != image_count:
            self.log.info("Implicitly filtered %d non owned images", image_count - len(images))

        for i in images:
            self.manager.retry(client.deregister_image, ImageId=i['ImageId'])

            if not self.data.get('delete-snapshots'):
                continue
            snap_ids = self.snap_expr.search(i) or ()
            for s in snap_ids:
                try:
                    self.manager.retry(client.delete_snapshot, SnapshotId=s)
                except ClientError as e:
                    if e.error['Code'] == 'InvalidSnapshot.InUse':
                        continue


@AMI.action_registry.register('remove-launch-permissions')
class RemoveLaunchPermissions(BaseAction):
    """Action to remove the ability to launch an instance from an AMI

    This action will remove any launch permissions granted to other
    AWS accounts from the image, leaving only the owner capable of
    launching it

    :example:

    .. code-block:: yaml

            policies:
              - name: ami-stop-share-old
                resource: ami
                filters:
                  - type: image-age
                    days: 60
                actions:
                  - remove-launch-permissions

    """

    schema = type_schema('remove-launch-permissions')
    permissions = ('ec2:ResetImageAttribute',)

    def process(self, images):
        client = local_session(self.manager.session_factory).client('ec2')
        for i in images:
            self.process_image(client, i)

    def process_image(self, client, image):
        client.reset_image_attribute(
            ImageId=image['ImageId'], Attribute="launchPermission")


@AMI.action_registry.register('copy')
class Copy(BaseAction):
    """Action to copy AMIs with optional encryption

    This action can copy AMIs while optionally encrypting or decrypting
    the target AMI. It is advised to use in conjunction with a filter.

    Note there is a max in flight of 5 per account/region.

    :example:

    .. code-block:: yaml

            policies:
              - name: ami-ensure-encrypted
                resource: ami
                filters:
                  - type: value
                    key: encrypted
                    value: true
                actions:
                  - type: copy
                    encrypt: true
                    key-id: 00000000-0000-0000-0000-000000000000
    """

    permissions = ('ec2:CopyImage',)
    schema = {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'type': {'enum': ['copy']},
            'name': {'type': 'string'},
            'description': {'type': 'string'},
            'region': {'type': 'string'},
            'encrypt': {'type': 'boolean'},
            'key-id': {'type': 'string'}
        }
    }

    def process(self, images):
        session = local_session(self.manager.session_factory)
        client = session.client(
            'ec2',
            region_name=self.data.get('region', None))

        for image in images:
            client.copy_image(
                Name=self.data.get('name', image['Name']),
                Description=self.data.get('description', image['Description']),
                SourceRegion=session.region_name,
                SourceImageId=image['ImageId'],
                Encrypted=self.data.get('encrypt', False),
                KmsKeyId=self.data.get('key-id', ''))


@AMI.filter_registry.register('image-age')
class ImageAgeFilter(AgeFilter):
    """Filters images based on the age (in days)

    :example:

    .. code-block:: yaml

            policies:
              - name: ami-remove-launch-permissions
                resource: ami
                filters:
                  - type: image-age
                    days: 30
    """

    date_attribute = "CreationDate"
    schema = type_schema(
        'image-age',
        op={'$ref': '#/definitions/filters_common/comparison_operators'},
        days={'type': 'number', 'minimum': 0})


@AMI.filter_registry.register('unused')
class ImageUnusedFilter(Filter):
    """Filters images based on usage

    true: image has no instances spawned from it
    false: image has instances spawned from it

    :example:

    .. code-block:: yaml

            policies:
              - name: ami-unused
                resource: ami
                filters:
                  - type: unused
                    value: true
    """

    schema = type_schema('unused', value={'type': 'boolean'})

    def get_permissions(self):
        return list(itertools.chain(*[
            self.manager.get_resource_manager(m).get_permissions()
            for m in ('asg', 'launch-config', 'ec2')]))

    def _pull_asg_images(self):
        asgs = self.manager.get_resource_manager('asg').resources()
        image_ids = set()
        lcfgs = set(a['LaunchConfigurationName'] for a in asgs if 'LaunchConfigurationName' in a)
        lcfg_mgr = self.manager.get_resource_manager('launch-config')

        if lcfgs:
            image_ids.update([
                lcfg['ImageId'] for lcfg in lcfg_mgr.resources()
                if lcfg['LaunchConfigurationName'] in lcfgs])

        tmpl_mgr = self.manager.get_resource_manager('launch-template-version')
        for tversion in tmpl_mgr.get_resources(
                list(tmpl_mgr.get_asg_templates(asgs).keys())):
            image_ids.add(tversion['LaunchTemplateData'].get('ImageId'))
        return image_ids

    def _pull_ec2_images(self):
        ec2_manager = self.manager.get_resource_manager('ec2')
        return set([i['ImageId'] for i in ec2_manager.resources()])

    def process(self, resources, event=None):
        images = self._pull_ec2_images().union(self._pull_asg_images())
        if self.data.get('value', True):
            return [r for r in resources if r['ImageId'] not in images]
        return [r for r in resources if r['ImageId'] in images]


@AMI.filter_registry.register('cross-account')
class AmiCrossAccountFilter(CrossAccountAccessFilter):

    schema = type_schema(
        'cross-account',
        # white list accounts
        whitelist_from=ValuesFrom.schema,
        whitelist={'type': 'array', 'items': {'type': 'string'}})

    permissions = ('ec2:DescribeImageAttribute',)

    def process_resource_set(self, client, accounts, resource_set):
        results = []
        for r in resource_set:
            attrs = self.manager.retry(
                client.describe_image_attribute,
                ImageId=r['ImageId'],
                Attribute='launchPermission')['LaunchPermissions']
            image_accounts = {a.get('Group') or a.get('UserId') for a in attrs}
            delta_accounts = image_accounts.difference(accounts)
            if delta_accounts:
                r['c7n:CrossAccountViolations'] = list(delta_accounts)
                results.append(r)
        return results

    def process(self, resources, event=None):
        results = []
        client = local_session(self.manager.session_factory).client('ec2')
        accounts = self.get_accounts()

        with self.executor_factory(max_workers=2) as w:
            futures = []
            for resource_set in chunks(resources, 20):
                futures.append(
                    w.submit(
                        self.process_resource_set, client, accounts, resource_set))
            for f in as_completed(futures):
                if f.exception():
                    self.log.error(
                        "Exception checking cross account access \n %s" % (
                            f.exception()))
                    continue
                results.extend(f.result())
        return results
