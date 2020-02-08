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

import pytest
from azure.common import AzureHttpError
from azure.mgmt.storage.models import StorageAccountListKeysResult, StorageAccountKey
from azure.storage.common import TokenCredential
from c7n_azure.session import Session
from c7n_azure.storage_utils import StorageUtilities
from c7n_azure.utils import ResourceIdParser
from mock import patch

from c7n.utils import local_session
from .azure_common import BaseTest, arm_template, requires_arm_polling


@requires_arm_polling
class StorageUtilsTest(BaseTest):
    def setUp(self):
        super(StorageUtilsTest, self).setUp()
        self.session = Session()
        StorageUtilities.get_storage_from_uri.cache_clear()

    @arm_template('storage.json')
    def test_get_storage_client_by_uri(self):
        account = self.setup_account()
        url = "https://" + account.name + ".blob.core.windows.net/testcontainer/extrafolder"
        blob_service, container_name, key_prefix = \
            StorageUtilities.get_blob_client_by_uri(url, self.session)
        self.assertIsNotNone(blob_service)
        self.assertEqual(container_name, "testcontainer")
        self.assertEqual(key_prefix, "extrafolder")

    @arm_template('storage.json')
    def test_get_storage_client_by_uri_extra_directories(self):
        account = self.setup_account()
        url = "https://" + account.name + \
              ".blob.core.windows.net/testcontainer/extrafolder/foo/bar"
        blob_service, container_name, key_prefix = \
            StorageUtilities.get_blob_client_by_uri(url, self.session)
        self.assertIsNotNone(blob_service)
        self.assertEqual(container_name, "testcontainer")
        self.assertEqual(key_prefix, "extrafolder/foo/bar")

    @arm_template('storage.json')
    def test_get_queue_client_by_uri(self):
        account = self.setup_account()
        url = "https://" + account.name + ".queue.core.windows.net/testcc"
        queue_service, queue_name = StorageUtilities.get_queue_client_by_uri(url, self.session)
        self.assertIsNotNone(queue_service)
        self.assertEqual(queue_name, "testcc")

    def test_get_queue_client_expired_token(self):
        """
        Exception handler should deal with a bad token by clearing
        cache and retrying.  So if we provide a bad token followed
        by a real one in our mock, we expect it to end up getting
        the real token.
        """
        real_token = StorageUtilities.get_storage_token(self.session)

        with patch('c7n_azure.storage_utils.QueueService.create_queue') as create_mock:
            with patch('c7n_azure.storage_utils.StorageUtilities.get_storage_token') as token_mock:
                error = AzureHttpError('', 403)
                error.error_code = 'AuthenticationFailed'

                # Two side effects: one with a bad token and an error,
                # and one with a good token and no error
                create_mock.side_effect = [error, None]
                token_mock.side_effect = [TokenCredential('fake'), real_token]

                url = "https://fake.queue.core.windows.net/testcc"
                queue_service, queue_name = \
                    StorageUtilities.get_queue_client_by_uri(url, self.session)

                # We end up with the real token (after a retry)
                self.assertEqual(real_token, queue_service.authentication)

    @arm_template('storage.json')
    def test_create_delete_queue_from_storage_account(self):
        account = self.setup_account()
        queue_name = 'testqueuecc'

        queue = \
            StorageUtilities.create_queue_from_storage_account(account, queue_name, self.session)

        self.assertTrue(queue)

        result = \
            StorageUtilities.delete_queue_from_storage_account(account, queue_name, self.session)

        self.assertTrue(result)

    @arm_template('storage.json')
    @pytest.mark.skiplive
    def test_cycle_queue_message_by_uri(self):
        account = self.setup_account()
        url = "https://" + account.name + ".queue.core.windows.net/testcyclemessage"

        queue_settings = StorageUtilities.get_queue_client_by_uri(url, self.session)
        StorageUtilities.put_queue_message(*queue_settings, content=u"hello queue")

        # Pull messages, should be 1
        messages = StorageUtilities.get_queue_messages(*queue_settings)
        self.assertEqual(len(messages), 1)

        # Read message and delete it from queue
        for message in messages:
            self.assertEqual(message.content, u"hello queue")
            StorageUtilities.delete_queue_message(*queue_settings, message=message)

        # Pull messages again, should be empty
        messages = StorageUtilities.get_queue_messages(*queue_settings)
        self.assertEqual(len(messages), 0)

    @arm_template('storage.json')
    def test_get_storage_token(self):
        token = StorageUtilities.get_storage_token(self.session)
        self.assertIsNotNone(token.token)

    def test_get_storage_primary_key(self):
        key1 = StorageAccountKey()
        key1.key_name = "key1"
        key1.value = "mock_storage_key"

        data = StorageAccountListKeysResult()
        data.keys = [key1]

        with patch(self._get_storage_client_string() + '.list_keys', return_value=data) \
                as list_keys_mock:
            primary_key = StorageUtilities.get_storage_primary_key(
                'mock_rg_group', 'mock_account', self.session)
            list_keys_mock.assert_called_with('mock_rg_group', 'mock_account')
            self.assertEqual(primary_key, data.keys[0].value)

    @arm_template('storage.json')
    def test_get_blob_client_from_storage_account_without_sas(self):
        account = self.setup_account()
        resource_group = ResourceIdParser.get_resource_group(account.id)
        blob_client = StorageUtilities.get_blob_client_from_storage_account(
            resource_group,
            account.name,
            self.session)

        self.assertIsNotNone(blob_client)

    @arm_template('storage.json')
    def test_get_blob_client_from_storage_account_without_sas_fails_sas_generation(self):
        with self.assertRaises(ValueError):
            account = self.setup_account()
            resource_group = ResourceIdParser.get_resource_group(account.id)
            blob_client = StorageUtilities.get_blob_client_from_storage_account(
                resource_group,
                account.name,
                self.session)

            # create container for package
            blob_client.create_container('test')
            blob_client.create_blob_from_text('test', 'test.txt', 'My test contents.')
            blob_client.generate_blob_shared_access_signature('test', 'test.txt')

    @arm_template('storage.json')
    def test_get_blob_client_from_storage_account_with_sas(self):
        account = self.setup_account()
        resource_group = ResourceIdParser.get_resource_group(account.id)
        blob_client = StorageUtilities.get_blob_client_from_storage_account(
            resource_group,
            account.name,
            self.session,
            True)

        # create sas token for blob
        blob_client.create_container('test')
        blob_client.create_blob_from_text('test', 'test.txt', 'My test contents.')
        sas = blob_client.generate_blob_shared_access_signature('test', 'test.txt')

        self.assertIsNotNone(sas)

    def _get_storage_client_string(self):
        client = local_session(Session)\
            .client('azure.mgmt.storage.StorageManagementClient').storage_accounts
        return client.__module__ + '.' + client.__class__.__name__
