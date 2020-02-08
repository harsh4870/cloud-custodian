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

from ..azure_common import BaseTest, arm_template, cassette_name
from c7n_azure.resources.key_vault import (KeyVaultUpdateAccessPolicyAction, WhiteListFilter,
                                           KeyVaultFirewallRulesFilter,
                                           KeyVaultFirewallBypassFilter)
from c7n_azure.session import Session
from c7n_azure.utils import GraphHelper
from mock import patch, Mock
from msrestazure.azure_exceptions import CloudError
from netaddr import IPSet
from parameterized import parameterized
import pytest
from requests import Response

from c7n.utils import local_session


class KeyVaultTest(BaseTest):
    def setUp(self):
        super(KeyVaultTest, self).setUp()

    def test_key_vault_schema_validate(self):
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'test-key-vault',
                'resource': 'azure.keyvault',
                'filters': [
                    {'type': 'whitelist',
                     'key': 'test'}
                ],
                'actions': [
                    {'type': 'update-access-policy',
                     'operation': 'add',
                     'access-policies': []}
                ]
            }, validate=True)
            self.assertTrue(p)

    @arm_template('keyvault.json')
    @cassette_name('common')
    def test_find_by_name(self):
        p = self.load_policy({
            'name': 'test-azure-keyvault',
            'resource': 'azure.keyvault',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cckeyvault1*'}],
        })
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_compare_permissions(self):
        p1 = {"keys": ['get'], "secrets": ['get'], "certificates": ['get']}
        p2 = {"keys": ['Get', 'List'], "secrets": ['Get', 'List'], "certificates": ['Get', 'List']}
        self.assertTrue(WhiteListFilter.compare_permissions(p1, p2))

        p1 = {"keys": ['delete']}
        p2 = {"keys": ['Get', 'List'], "secrets": ['Get', 'List'], "certificates": ['Get', 'List']}
        self.assertFalse(WhiteListFilter.compare_permissions(p1, p2))

        p1 = {"secrets": ['delete']}
        p2 = {"keys": ['Get', 'List'], "secrets": ['Get', 'List'], "certificates": ['Get', 'List']}
        self.assertFalse(WhiteListFilter.compare_permissions(p1, p2))

        p1 = {"certificates": ['delete']}
        p2 = {"keys": ['Get', 'List'], "secrets": ['Get', 'List'], "certificates": ['Get', 'List']}
        self.assertFalse(WhiteListFilter.compare_permissions(p1, p2))

        p1 = {}
        p2 = {"keys": ['Get', 'List'], "secrets": ['Get', 'List'], "certificates": ['Get', 'List']}
        self.assertTrue(WhiteListFilter.compare_permissions(p1, p2))

        p1 = {"keys": ['get'], "secrets": ['get'], "certificates": ['get']}
        p2 = {}
        self.assertFalse(WhiteListFilter.compare_permissions(p1, p2))

    # Requires Graph access
    @arm_template('keyvault.json')
    @pytest.mark.skiplive
    def test_whitelist(self):
        """Tests basic whitelist functionality"""
        p = self.load_policy({
            'name': 'test-key-vault',
            'resource': 'azure.keyvault',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cckeyvault1*'},
                {'not': [
                    {'type': 'whitelist',
                     'key': 'principalName',
                     'users': ['account1@sample.com']}
                ]}
            ]
        })
        resources = p.run()
        self.assertEqual(len(resources), 1)

    @arm_template('keyvault-no-policies.json')
    def test_whitelist_zero_access_policies(self):
        """Tests that a keyvault with 0 access policies is processed properly
        and doesn't raise an exception.
        """
        p = self.load_policy({
            'name': 'test-key-vault',
            'resource': 'azure.keyvault',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cckeyvault2*'},
                {'not': [
                    {'type': 'whitelist',
                     'key': 'principalName',
                     'users': ['account1@sample.com']}
                ]}
            ]
        })
        resources = p.run()
        self.assertEqual(len(resources), 0)

    @arm_template('keyvault.json')
    @patch.object(GraphHelper, 'get_principal_dictionary')
    def test_whitelist_not_authorized(self, get_principal_dictionary):
        """Tests that an exception is thrown when both:
          The Microsoft Graph call fails.

          This is mocked because it is impractical to have
          identities with varying levels of graph access for
          live test runs or recordings"""

        mock_response = Mock(spec=Response)
        mock_response.status_code = 403
        mock_response.text = 'forbidden'
        get_principal_dictionary.side_effect = CloudError(mock_response)

        p = self.load_policy({
            'name': 'test-key-vault',
            'resource': 'azure.keyvault',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cckeyvault1*'},
                {'not': [
                    {'type': 'whitelist',
                     'key': 'principalName',
                     'users': ['account1@sample.com']}
                ]}
            ]
        })

        with self.assertRaises(CloudError) as e:
            p.run()

        self.assertEqual(403, e.exception.status_code)

    def test_update_access_policy_action(self):
        with patch(self._get_key_vault_client_string() + '.update_access_policy')\
                as access_policy_action_mock:
            p = self.load_policy({
                'name': 'test-azure-keyvault',
                'resource': 'azure.keyvault',
                'filters': [
                    {'type': 'value',
                     'key': 'name',
                     'op': 'glob',
                     'value_type': 'normalize',
                     'value': 'cckeyvault1*'}],
                'actions': [
                    {'type': 'update-access-policy',
                     'operation': 'replace',
                     'access-policies': [{
                         'tenant-id': '00000000-0000-0000-0000-000000000000',
                         'object-id': '11111111-1111-1111-1111-111111111111',
                         'permissions': {'keys': ['Get']}}]}]
            })

            p.run()
            access_policy_action_mock.assert_called()

    def test_transform_access_policies(self):
        mock_access_policies = [{"object-id": "mockObjectId",
                                 "tenant-id": "mockTenantId",
                                 "permissions": {"keys": ["Get"]}}]
        transformed_access_policies = KeyVaultUpdateAccessPolicyAction._transform_access_policies(
            mock_access_policies).get("accessPolicies")[0]
        self.assertTrue("objectId" in transformed_access_policies)
        self.assertTrue("tenantId" in transformed_access_policies)
        self.assertTrue("permissions" in transformed_access_policies)

    def _get_key_vault_client_string(self):
        client = local_session(Session) \
            .client('azure.mgmt.keyvault.KeyVaultManagementClient').vaults
        return client.__module__ + '.' + client.__class__.__name__

    @arm_template('keyvault.json')
    @cassette_name('common')
    def test_firewall_rules_include(self):
        p = self.load_policy({
            'name': 'test-azure-keyvault',
            'resource': 'azure.keyvault',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value': 'cckeyvault1*'},
                {'type': 'firewall-rules',
                 'include': ['1.0.0.0']}],
        })
        resources = p.run()
        self.assertEqual(len(resources), 1)

    @arm_template('keyvault.json')
    @cassette_name('common')
    def test_firewall_rules_not_include_all_ranges(self):
        p = self.load_policy({
            'name': 'test-azure-keyvault',
            'resource': 'azure.keyvault',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value': 'cckeyvault1*'},
                {'type': 'firewall-rules',
                 'include': ['1.0.0.0', '127.0.0.1']}],
        }, validate=True)
        resources = p.run()
        self.assertEqual(0, len(resources))

    @arm_template('keyvault.json')
    @cassette_name('common')
    def test_firewall_rules_include_cidr(self):
        p = self.load_policy({
            'name': 'test-azure-keyvault',
            'resource': 'azure.keyvault',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value': 'cckeyvault1*'},
                {'type': 'firewall-rules',
                 'include': ['128.0.0.0/1']}],
        }, validate=True)
        resources = p.run()
        self.assertEqual(1, len(resources))

    @arm_template('keyvault.json')
    @cassette_name('common')
    def test_firewall_rules_not_include_cidr(self):
        p = self.load_policy({
            'name': 'test-azure-keyvault',
            'resource': 'azure.keyvault',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value': 'cckeyvault1*'},
                {'type': 'firewall-rules',
                 'include': ['127.0.0.0/8']}],
        }, validate=True)
        resources = p.run()
        self.assertEqual(0, len(resources))

    @arm_template('keyvault.json')
    @cassette_name('common')
    def test_firewall_rules_equal(self):
        p = self.load_policy({
            'name': 'test-azure-keyvault',
            'resource': 'azure.keyvault',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value': 'cckeyvault1*'},
                {'type': 'firewall-rules',
                 'equal': ['0.0.0.0-126.255.255.255', '128.0.0.0-255.255.255.255']}],
        }, validate=True)
        resources = p.run()
        self.assertEqual(1, len(resources))

    @arm_template('keyvault.json')
    @cassette_name('common')
    def test_firewall_rules_not_equal(self):
        p = self.load_policy({
            'name': 'test-azure-keyvault',
            'resource': 'azure.keyvault',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value': 'cckeyvault1*'},
                {'type': 'firewall-rules',
                 'equal': ['0.0.0.0-126.255.255.255', '128.0.0.0-255.255.255.254']}],
        }, validate=True)
        resources = p.run()
        self.assertEqual(0, len(resources))

    @arm_template('keyvault.json')
    @cassette_name('common')
    def test_firewall_bypass(self):
        p = self.load_policy({
            'name': 'test-azure-keyvault',
            'resource': 'azure.keyvault',
            'filters': [
                {'type': 'firewall-bypass',
                 'mode': 'equal',
                 'list': ['AzureServices']}],
        })
        resources = p.run()
        self.assertEqual(1, len(resources))


class KeyVaultFirewallFilterTest(BaseTest):

    def test_query_empty_network_acl(self):
        resource = {'properties': {}}
        expected = IPSet(['0.0.0.0/0'])
        self.assertEqual(expected, self._get_filter()._query_rules(resource))

    def test_query_default_action_allow(self):
        resource = {'properties': {'networkAcls': {'defaultAction': 'Allow'}}}
        expected = IPSet(['0.0.0.0/0'])
        self.assertEqual(expected, self._get_filter()._query_rules(resource))

    def test_query_default_action_deny(self):
        resource = {'properties': {'networkAcls': {'defaultAction': 'Deny',
                                                   'ipRules': [{'value': '10.0.0.0/16'},
                                                               {'value': '8.8.8.8'}]}}}
        expected = IPSet(['8.8.8.8', '10.0.0.0/16'])
        self.assertEqual(expected, self._get_filter()._query_rules(resource))

    def _get_filter(self, mode='equal'):
        data = {mode: ['10.0.0.0/8', '127.0.0.1']}
        return KeyVaultFirewallRulesFilter(data, Mock())


class KeyVaultFirewallBypassFilterTest(BaseTest):

    scenarios = [
        [{}, []],
        [{'networkAcls': {'defaultAction': 'Allow', 'bypass': ''}}, ['AzureServices']],
        [{'networkAcls': {'defaultAction': 'Deny', 'bypass': ''}}, []],
        [{'networkAcls': {'defaultAction': 'Deny', 'bypass': 'AzureServices'}},
         ['AzureServices']],
    ]

    @parameterized.expand(scenarios)
    def test_run(self, properties, expected):
        resource = {'properties': properties}
        f = KeyVaultFirewallBypassFilter({'mode': 'equal', 'list': []})
        self.assertEqual(expected, f._query_bypass(resource))
