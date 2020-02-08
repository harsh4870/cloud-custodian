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

import sys
import types

from .azure_common import BaseTest, DEFAULT_SUBSCRIPTION_ID
from c7n_azure.tags import TagHelper
from c7n_azure.utils import (AppInsightsHelper, ManagedGroupHelper, Math, PortsRangeHelper,
                             ResourceIdParser, StringUtils, custodian_azure_send_override,
                             get_keyvault_secret, get_service_tag_ip_space, is_resource_group_id,
                             is_resource_group)
from mock import patch, Mock

from c7n.config import Bag
import pytest

try:
    from importlib import reload
except Exception:
    pass  # Python 2.7 has reload built-in

RESOURCE_ID = (
    "/subscriptions/%s/resourceGroups/"
    "rgtest/providers/Microsoft.Compute/virtualMachines/nametest" % DEFAULT_SUBSCRIPTION_ID)


RESOURCE_ID_CHILD = (
    "/subscriptions/%s/resourceGroups/"
    "rgtest/providers/Microsoft.Sql/servers/testserver/"
    "databases/testdb" % DEFAULT_SUBSCRIPTION_ID)

GUID = '00000000-0000-0000-0000-000000000000'


class UtilsTest(BaseTest):
    def setUp(self):
        super(UtilsTest, self).setUp()

    def test_get_subscription_id(self):
        self.assertEqual(ResourceIdParser.get_subscription_id(RESOURCE_ID), DEFAULT_SUBSCRIPTION_ID)

    def test_get_namespace(self):
        self.assertEqual(ResourceIdParser.get_namespace(RESOURCE_ID), "Microsoft.Compute")
        self.assertEqual(ResourceIdParser.get_namespace(RESOURCE_ID_CHILD), "Microsoft.Sql")

    def test_get_resource_group(self):
        self.assertEqual(ResourceIdParser.get_resource_group(RESOURCE_ID), "rgtest")

    def test_get_resource_type(self):

        self.assertEqual(ResourceIdParser.get_resource_type(RESOURCE_ID), "virtualMachines")
        self.assertEqual(ResourceIdParser.get_resource_type(RESOURCE_ID_CHILD), "servers/databases")

    def test_get_full_type(self):
        self.assertEqual(ResourceIdParser.get_full_type(RESOURCE_ID),
                         "Microsoft.Compute/virtualMachines")

    def test_resource_name(self):
        self.assertEqual(ResourceIdParser.get_resource_name(RESOURCE_ID), "nametest")

    def test_math_mean(self):
        self.assertEqual(Math.mean([4, 5, None, 3]), 4)
        self.assertEqual(Math.mean([None]), 0)
        self.assertEqual(Math.mean([3, 4]), 3.5)

    def test_math_sum(self):
        self.assertEqual(Math.sum([4, 5, None, 3]), 12)
        self.assertEqual(Math.sum([None]), 0)
        self.assertEqual(Math.sum([3.5, 4]), 7.5)

    def test_string_utils_equal(self):
        # Case insensitive matches
        self.assertTrue(StringUtils.equal("FOO", "foo"))
        self.assertTrue(StringUtils.equal("fOo", "FoO"))
        self.assertTrue(StringUtils.equal("ABCDEFGH", "abcdefgh"))
        self.assertFalse(StringUtils.equal("Foo", "Bar"))

        # Case sensitive matches
        self.assertFalse(StringUtils.equal("Foo", "foo", False))
        self.assertTrue(StringUtils.equal("foo", "foo", False))
        self.assertTrue(StringUtils.equal("fOo", "fOo", False))
        self.assertFalse(StringUtils.equal("Foo", "Bar"))

        # Strip whitespace matches
        self.assertTrue(StringUtils.equal(" Foo ", "foo"))
        self.assertTrue(StringUtils.equal("Foo", " foo "))
        self.assertTrue(StringUtils.equal(" Foo ", "Foo", False))
        self.assertTrue(StringUtils.equal("Foo", " Foo ", False))

        # Returns false for non string types
        self.assertFalse(StringUtils.equal(1, "foo"))
        self.assertFalse(StringUtils.equal("foo", 1))
        self.assertFalse(StringUtils.equal(True, False))

    def test_get_tag_value(self):
        resource = {'tags': {'tag1': 'value1', 'tAg2': 'VaLuE2', 'TAG3': 'VALUE3'}}

        self.assertEqual(TagHelper.get_tag_value(resource, 'tag1', True), 'value1')
        self.assertEqual(TagHelper.get_tag_value(resource, 'tag2', True), 'VaLuE2')
        self.assertEqual(TagHelper.get_tag_value(resource, 'tag3', True), 'VALUE3')

    def test_get_ports(self):
        self.assertEqual(PortsRangeHelper.get_ports_set_from_string("5, 4-5, 9"), set([4, 5, 9]))
        rule = {'properties': {'destinationPortRange': '10-12'}}
        self.assertEqual(PortsRangeHelper.get_ports_set_from_rule(rule), set([10, 11, 12]))
        rule = {'properties': {'destinationPortRanges': ['80', '10-12']}}
        self.assertEqual(PortsRangeHelper.get_ports_set_from_rule(rule), set([10, 11, 12, 80]))

    def test_validate_ports_string(self):
        self.assertEqual(PortsRangeHelper.validate_ports_string('80'), True)
        self.assertEqual(PortsRangeHelper.validate_ports_string('22-26'), True)
        self.assertEqual(PortsRangeHelper.validate_ports_string('80,22'), True)
        self.assertEqual(PortsRangeHelper.validate_ports_string('80,22-26'), True)
        self.assertEqual(PortsRangeHelper.validate_ports_string('80,22-26,30-34'), True)
        self.assertEqual(PortsRangeHelper.validate_ports_string('65537'), False)
        self.assertEqual(PortsRangeHelper.validate_ports_string('-1'), False)
        self.assertEqual(PortsRangeHelper.validate_ports_string('10-8'), False)
        self.assertEqual(PortsRangeHelper.validate_ports_string('80,30,25-65538'), False)
        self.assertEqual(PortsRangeHelper.validate_ports_string('65536-65537'), False)

    def test_get_ports_strings_from_list(self):
        self.assertEqual(PortsRangeHelper.get_ports_strings_from_list([]),
                         [])
        self.assertEqual(PortsRangeHelper.get_ports_strings_from_list([10, 11]),
                         ['10-11'])
        self.assertEqual(PortsRangeHelper.get_ports_strings_from_list([10, 12, 13, 14]),
                         ['10', '12-14'])
        self.assertEqual(PortsRangeHelper.get_ports_strings_from_list([10, 12, 13, 14, 20, 21, 22]),
                         ['10', '12-14', '20-22'])

    def test_build_ports_dict(self):
        securityRules = [
            {'properties': {'destinationPortRange': '80-84',
                            'priority': 100,
                            'direction': 'Outbound',
                            'access': 'Allow',
                            'protocol': 'TCP'}},
            {'properties': {'destinationPortRange': '85-89',
                            'priority': 110,
                            'direction': 'Outbound',
                            'access': 'Allow',
                            'protocol': 'UDP'}},
            {'properties': {'destinationPortRange': '80-84',
                            'priority': 120,
                            'direction': 'Inbound',
                            'access': 'Deny',
                            'protocol': 'TCP'}},
            {'properties': {'destinationPortRange': '85-89',
                            'priority': 130,
                            'direction': 'Inbound',
                            'access': 'Deny',
                            'protocol': 'UDP'}},
            {'properties': {'destinationPortRange': '80-89',
                            'priority': 140,
                            'direction': 'Inbound',
                            'access': 'Allow',
                            'protocol': '*'}}]
        nsg = {'properties': {'securityRules': securityRules}}

        self.assertEqual(PortsRangeHelper.build_ports_dict(nsg, 'Inbound', 'TCP'),
                         {k: k > 84 for k in range(80, 90)})
        self.assertEqual(PortsRangeHelper.build_ports_dict(nsg, 'Inbound', 'UDP'),
                         {k: k < 85 for k in range(80, 90)})
        self.assertEqual(PortsRangeHelper.build_ports_dict(nsg, 'Inbound', '*'),
                         {k: False for k in range(80, 90)})
        self.assertEqual(PortsRangeHelper.build_ports_dict(nsg, 'Outbound', 'TCP'),
                         {k: True for k in range(80, 85)})
        self.assertEqual(PortsRangeHelper.build_ports_dict(nsg, 'Outbound', 'UDP'),
                         {k: True for k in range(85, 90)})
        self.assertEqual(PortsRangeHelper.build_ports_dict(nsg, 'Outbound', '*'),
                         {k: True for k in range(80, 90)})

    def test_snake_to_camel(self):
        self.assertEqual(StringUtils.snake_to_camel(""), "")
        self.assertEqual(StringUtils.snake_to_camel("test"), "test")
        self.assertEqual(StringUtils.snake_to_camel("test_abc"), "testAbc")
        self.assertEqual(StringUtils.snake_to_camel("test_abc_def"), "testAbcDef")

    def test_naming_hash(self):
        source = 'Lorem ipsum dolor sit amet'
        source2 = 'amet sit dolor ipsum Lorem'
        self.assertEqual(StringUtils.naming_hash(source), '16aba539')
        self.assertEqual(StringUtils.naming_hash(source, 10), '16aba5393a')
        self.assertNotEqual(StringUtils.naming_hash(source), StringUtils.naming_hash(source2))

    @patch('azure.mgmt.applicationinsights.operations.ComponentsOperations.get',
           return_value=type(str('result_data'), (), {'instrumentation_key': GUID}))
    def test_app_insights_get_instrumentation_key(self, mock_handler_run):
        self.assertEqual(AppInsightsHelper.get_instrumentation_key('azure://' + GUID), GUID)
        self.assertEqual(AppInsightsHelper.get_instrumentation_key('azure://resourceGroup/name'),
                         GUID)
        mock_handler_run.assert_called_once_with('resourceGroup', 'name')

    @patch('c7n_azure.utils.send_logger.debug')
    def test_custodian_azure_send_override_200(self, logger):
        mock = Mock()
        mock.send = types.MethodType(custodian_azure_send_override, mock)

        response_dict = {
            'headers': {'x-ms-ratelimit-remaining-subscription-reads': '12000'},
            'status_code': 200
        }
        mock.orig_send.return_value = type(str('response'), (), response_dict)
        mock.send('')

        self.assertEqual(mock.orig_send.call_count, 1)
        self.assertEqual(logger.call_count, 2)

    @patch('c7n_azure.utils.send_logger.debug')
    @patch('c7n_azure.utils.send_logger.warning')
    def test_custodian_azure_send_override_429(self, logger_debug, logger_warning):
        mock = Mock()
        mock.send = types.MethodType(custodian_azure_send_override, mock)

        response_dict = {
            'headers': {'Retry-After': 0},
            'status_code': 429
        }
        mock.orig_send.return_value = type(str('response'), (), response_dict)
        mock.send('')

        self.assertEqual(mock.orig_send.call_count, 3)
        self.assertEqual(logger_debug.call_count, 3)
        self.assertEqual(logger_warning.call_count, 3)

    @patch('c7n_azure.utils.send_logger.error')
    def test_custodian_azure_send_override_429_long_retry(self, logger):
        mock = Mock()
        mock.send = types.MethodType(custodian_azure_send_override, mock)

        response_dict = {
            'headers': {'Retry-After': 60},
            'status_code': 429
        }
        mock.orig_send.return_value = type(str('response'), (), response_dict)
        mock.send('')

        self.assertEqual(mock.orig_send.call_count, 1)
        self.assertEqual(logger.call_count, 1)

    managed_group_return_value = ([
        Bag({'name': '/providers/Microsoft.Management/managementGroups/cc-test-1',
             'type': '/providers/Microsoft.Management/managementGroups'}),
        Bag({'name': '/providers/Microsoft.Management/managementGroups/cc-test-2',
             'type': '/providers/Microsoft.Management/managementGroups'}),
        Bag({'name': DEFAULT_SUBSCRIPTION_ID,
             'type': '/subscriptions'}),
        Bag({'name': GUID,
             'type': '/subscriptions'}),
    ])

    @patch('azure.mgmt.managementgroups.operations.EntitiesOperations.list',
           return_value=managed_group_return_value)
    def test_managed_group_helper(self, _1):
        sub_ids = ManagedGroupHelper.get_subscriptions_list('test-group', "")
        self.assertEqual(sub_ids, [DEFAULT_SUBSCRIPTION_ID, GUID])

    @patch('msrestazure.azure_active_directory.MSIAuthentication')
    def test_get_keyvault_secret(self, _1):
        mock = Mock()
        mock.value = '{"client_id": "client", "client_secret": "secret"}'
        with patch('azure.common.credentials.ServicePrincipalCredentials.__init__',
                   return_value=None), \
                patch('azure.keyvault.v7_0.KeyVaultClient.get_secret', return_value=mock):

            reload(sys.modules['c7n_azure.utils'])

            result = get_keyvault_secret(None, 'https://testkv.vault.net/secrets/testsecret/123412')
            self.assertEqual(result, mock.value)

    # Test relies on substitute data in Azure Common, not designed for live data
    @pytest.mark.skiplive
    def test_get_service_tag_ip_space(self):
        # Get with region
        result = get_service_tag_ip_space('ApiManagement', 'WestUS')
        self.assertEqual(3, len(result))
        self.assertEqual({"13.64.39.16/32",
                          "40.112.242.148/31",
                          "40.112.243.240/28"}, set(result))

        # Get without region
        result = get_service_tag_ip_space('ApiManagement')
        self.assertEqual(5, len(result))
        self.assertEqual({"13.69.64.76/31",
                          "13.69.66.144/28",
                          "23.101.67.140/32",
                          "51.145.179.78/32",
                          "137.117.160.56/32"}, set(result))

        # Invalid tag
        result = get_service_tag_ip_space('foo')
        self.assertEqual(0, len(result))

    def test_is_resource_group_id(self):
        self.assertTrue(is_resource_group_id('/subscriptions/GUID/resourceGroups/rg'))
        self.assertTrue(is_resource_group_id('/subscriptions/GUID/resourceGroups/rg/'))
        self.assertTrue(is_resource_group_id('/Subscriptions/GUID/resourcegroups/rg'))

        self.assertFalse(is_resource_group_id('/subscriptions/GUID/rg/'))
        self.assertFalse(is_resource_group_id('subscriptions/GUID/rg/'))
        self.assertFalse(is_resource_group_id('/GUID/rg/'))
        self.assertFalse(is_resource_group_id('/subscriptions/GUID/rg/providers/vm/vm'))
        self.assertFalse(is_resource_group_id('/subscriptions/GUID/rg/providers'))
        self.assertFalse(is_resource_group_id('/subscriptions/GUID/rg/p'))

    def test_is_resource_group(self):
        self.assertTrue(is_resource_group({'type': 'resourceGroups'}))
        self.assertFalse(is_resource_group({'type': 'virtualMachines'}))
