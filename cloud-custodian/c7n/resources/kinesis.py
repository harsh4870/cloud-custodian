# Copyright 2016-2017 Capital One Services, LLC
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

import jmespath

from c7n.actions import Action
from c7n.manager import resources
from c7n.query import QueryResourceManager, TypeInfo
from c7n.tags import universal_augment
from c7n.utils import local_session, type_schema, get_retry


@resources.register('kinesis')
class KinesisStream(QueryResourceManager):
    retry = staticmethod(
        get_retry((
            'LimitExceededException',)))

    class resource_type(TypeInfo):
        service = 'kinesis'
        arn_type = 'stream'
        enum_spec = ('list_streams', 'StreamNames', None)
        detail_spec = (
            'describe_stream', 'StreamName', None, 'StreamDescription')
        name = id = 'StreamName'
        dimension = 'StreamName'
        universal_taggable = True

    def augment(self, resources):
        return universal_augment(
            self, super(KinesisStream, self).augment(resources))


@KinesisStream.action_registry.register('encrypt')
class Encrypt(Action):

    schema = type_schema('encrypt',
                         key={'type': 'string'},
                         required=('key',))

    # not see any documentation on what permission is actually neeeded.
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazonkinesis.html
    permissions = ("kinesis:UpdateShardCount",)

    def process(self, resources):
        # get KeyId
        key = "alias/" + self.data.get('key')
        self.key_id = local_session(self.manager.session_factory).client(
            'kms').describe_key(KeyId=key)['KeyMetadata']['KeyId']
        client = local_session(self.manager.session_factory).client('kinesis')
        for r in resources:
            if not r['StreamStatus'] == 'ACTIVE':
                continue
            client.start_stream_encryption(
                StreamName=r['StreamName'],
                EncryptionType='KMS',
                KeyId=self.key_id
            )


@KinesisStream.action_registry.register('delete')
class Delete(Action):

    schema = type_schema('delete')
    permissions = ("kinesis:DeleteStream",)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('kinesis')
        not_active = [r['StreamName'] for r in resources
                      if r['StreamStatus'] != 'ACTIVE']
        self.log.warning(
            "The following streams cannot be deleted (wrong state): %s" % (
                ", ".join(not_active)))
        for r in resources:
            if not r['StreamStatus'] == 'ACTIVE':
                continue
            client.delete_stream(
                StreamName=r['StreamName'])


@resources.register('firehose')
class DeliveryStream(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'firehose'
        arn_type = 'deliverystream'
        enum_spec = ('list_delivery_streams', 'DeliveryStreamNames', None)
        detail_spec = (
            'describe_delivery_stream', 'DeliveryStreamName', None,
            'DeliveryStreamDescription')
        name = id = 'DeliveryStreamName'
        date = 'CreateTimestamp'
        dimension = 'DeliveryStreamName'
        universal_taggable = object()

    def augment(self, resources):
        return universal_augment(
            self, super(DeliveryStream, self).augment(resources))


@DeliveryStream.action_registry.register('delete')
class FirehoseDelete(Action):

    schema = type_schema('delete')
    permissions = ("firehose:DeleteDeliveryStream",)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('firehose')
        creating = [r['DeliveryStreamName'] for r in resources
                    if r['DeliveryStreamStatus'] == 'CREATING']
        if creating:
            self.log.warning(
                "These delivery streams can't be deleted (wrong state): %s" % (
                    ", ".join(creating)))
        for r in resources:
            if not r['DeliveryStreamStatus'] == 'ACTIVE':
                continue
            client.delete_delivery_stream(
                DeliveryStreamName=r['DeliveryStreamName'])


@DeliveryStream.action_registry.register('encrypt-s3-destination')
class FirehoseEncryptS3Destination(Action):
    """Action to set encryption key a Firehose S3 destination

    :example:

    .. code-block:: yaml

            policies:
              - name: encrypt-s3-destination
                resource: firehose
                filters:
                  - KmsMasterKeyId: absent
                actions:
                  - type: encrypt-s3-destination
                    key_arn: <arn of KMS key/alias>
    """
    schema = type_schema(
        'encrypt-s3-destination',
        key_arn={'type': 'string'}, required=('key_arn',))

    permissions = ("firehose:UpdateDestination",)

    DEST_MD = {
        'SplunkDestinationDescription': {
            'update': 'SplunkDestinationUpdate',
            'clear': ['S3BackupMode'],
            'encrypt_path': 'S3DestinationDescription.EncryptionConfiguration',
            'remap': [('S3DestinationDescription', 'S3Update')]
        },
        'ElasticsearchDestinationDescription': {
            'update': 'ElasticsearchDestinationUpdate',
            'clear': ['S3BackupMode'],
            'encrypt_path': 'S3DestinationDescription.EncryptionConfiguration',
            'remap': [('S3DestinationDescription', 'S3Update')],
        },
        'ExtendedS3DestinationDescription': {
            'update': 'ExtendedS3DestinationUpdate',
            'clear': ['S3BackupMode'],
            'encrypt_path': 'EncryptionConfiguration',
            'remap': []
        },
        'RedshiftDestinationDescription': {
            'update': 'RedshiftDestinationUpdate',
            'clear': ['S3BackupMode', "ClusterJDBCURL", "CopyCommand", "Username"],
            'encrypt_path': 'S3DestinationDescription.EncryptionConfiguration',
            'remap': [('S3DestinationDescription', 'S3Update')]
        },
    }

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('firehose')
        key = self.data.get('key_arn')
        for r in resources:
            if not r['DeliveryStreamStatus'] == 'ACTIVE':
                continue
            version = r['VersionId']
            name = r['DeliveryStreamName']
            d = r['Destinations'][0]
            destination_id = d['DestinationId']

            for dtype, dmetadata in self.DEST_MD.items():
                if dtype not in d:
                    continue
                dinfo = d[dtype]
                for k in dmetadata['clear']:
                    dinfo.pop(k, None)
                if dmetadata['encrypt_path']:
                    encrypt_info = jmespath.search(dmetadata['encrypt_path'], dinfo)
                else:
                    encrypt_info = dinfo
                encrypt_info.pop('NoEncryptionConfig', None)
                encrypt_info['KMSEncryptionConfig'] = {'AWSKMSKeyARN': key}

                for old_k, new_k in dmetadata['remap']:
                    if old_k in dinfo:
                        dinfo[new_k] = dinfo.pop(old_k)
                params = dict(DeliveryStreamName=name,
                              DestinationId=destination_id,
                              CurrentDeliveryStreamVersionId=version)
                params[dmetadata['update']] = dinfo
                client.update_destination(**params)


@resources.register('kinesis-analytics')
class AnalyticsApp(QueryResourceManager):

    class resource_type(TypeInfo):
        service = "kinesisanalytics"
        enum_spec = ('list_applications', 'ApplicationSummaries', None)
        detail_spec = ('describe_application', 'ApplicationName',
                       'ApplicationName', 'ApplicationDetail')
        name = "ApplicationName"
        arn = id = "ApplicationARN"
        arn_type = 'application'
        universal_taggable = object()

    def augment(self, resources):
        return universal_augment(
            self, super(AnalyticsApp, self).augment(resources))


@AnalyticsApp.action_registry.register('delete')
class AppDelete(Action):

    schema = type_schema('delete')
    permissions = ("kinesisanalytics:DeleteApplication",)

    def process(self, resources):
        client = local_session(
            self.manager.session_factory).client('kinesisanalytics')
        for r in resources:
            client.delete_application(
                ApplicationName=r['ApplicationName'],
                CreateTimestamp=r['CreateTimestamp'])
