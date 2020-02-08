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

import collections
import datetime

from ..azure_common import BaseTest, cassette_name, arm_template
from c7n_azure.resources.sqlserver import SqlServerFirewallRulesFilter, \
    SqlServerFirewallBypassFilter
from mock import patch, Mock
from netaddr import IPRange, IPSet
from parameterized import parameterized

IpRange = collections.namedtuple('IpRange', 'start_ip_address end_ip_address')


class SqlServerTest(BaseTest):

    TEST_DATE = datetime.datetime(2019, 4, 21, 14, 10, 00)

    def test_sql_server_schema_validate(self):
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'test-policy-assignment',
                'resource': 'azure.sql-server'
            }, validate=True)
            self.assertTrue(p)

            # test alias for back-compatibility
            p = self.load_policy({
                'name': 'test-policy-assignment',
                'resource': 'azure.sqlserver'
            }, validate=True)
            self.assertTrue(p)

    # run ./templates/provision.sh sqlserver to deploy required resource.
    def test_find_by_name(self):
        p = self.load_policy({
            'name': 'test-azure-sql-server',
            'resource': 'azure.sqlserver',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctestsqlserver*'}],
        })
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_metric_elastic_exclude(self):
        p = self.load_policy({
            'name': 'test-azure-sql-server',
            'resource': 'azure.sqlserver',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctestsqlserver*'},
                {'type': 'metric',
                 'metric': 'dtu_consumption_percent',
                 'op': 'lt',
                 'aggregation': 'average',
                 'threshold': 10,
                 'timeframe': 72,
                 'filter': "ElasticPoolResourceId eq '*'"
                 }],
        })
        resources = p.run()
        self.assertEqual(len(resources), 0)

    def test_metric_elastic_include(self):
        p = self.load_policy({
            'name': 'test-azure-sql-server',
            'resource': 'azure.sqlserver',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctestsqlserver*'},
                {'type': 'metric',
                 'metric': 'dtu_consumption_percent',
                 'op': 'lt',
                 'aggregation': 'average',
                 'threshold': 10,
                 'timeframe': 72,
                 'filter': "ElasticPoolResourceId eq '*'",
                 'no_data_action': 'include'
                 }],
        })
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_metric_database(self):
        p = self.load_policy({
            'name': 'test-azure-sql-server',
            'resource': 'azure.sqlserver',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctestsqlserver*'},
                {'type': 'metric',
                 'metric': 'dtu_consumption_percent',
                 'op': 'lt',
                 'aggregation': 'average',
                 'threshold': 10,
                 'timeframe': 72,
                 'filter': "DatabaseResourceId eq '*'"
                 }],
        })
        resources = p.run()
        self.assertEqual(len(resources), 1)

    @cassette_name('firewall')
    def test_firewall_rules_include_range(self):
        p = self.load_policy({
            'name': 'test-azure-sql-server',
            'resource': 'azure.sqlserver',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctestsqlserver*'},
                {'type': 'firewall-rules',
                 'include': ['1.2.2.128-1.2.2.255']}],
        }, validate=True)
        resources = p.run()
        self.assertEqual(1, len(resources))

    @cassette_name('firewall')
    def test_firewall_rules_not_include_all_ranges(self):
        p = self.load_policy({
            'name': 'test-azure-sql-server',
            'resource': 'azure.sqlserver',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctestsqlserver*'},
                {'type': 'firewall-rules',
                 'include': ['0.0.0.0-0.0.0.1']}],
        }, validate=True)
        resources = p.run()
        self.assertEqual(0, len(resources))

    @cassette_name('firewall')
    def test_firewall_rules_include_cidr(self):
        p = self.load_policy({
            'name': 'test-azure-sql-server',
            'resource': 'azure.sqlserver',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctestsqlserver*'},
                {'type': 'firewall-rules',
                 'include': ['1.2.2.128/25']}],
        }, validate=True)
        resources = p.run()
        self.assertEqual(1, len(resources))

    @cassette_name('firewall')
    def test_firewall_rules_not_include_cidr(self):
        p = self.load_policy({
            'name': 'test-azure-sql-server',
            'resource': 'azure.sqlserver',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctestsqlserver*'},
                {'type': 'firewall-rules',
                 'include': ['2.2.2.128/25']}],
        }, validate=True)
        resources = p.run()
        self.assertEqual(0, len(resources))

    @cassette_name('firewall')
    def test_firewall_rules_equal(self):
        p = self.load_policy({
            'name': 'test-azure-sql-server',
            'resource': 'azure.sqlserver',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctestsqlserver*'},
                {'type': 'firewall-rules',
                 'equal': ['1.2.2.128/25']}],
        }, validate=True)
        resources = p.run()
        self.assertEqual(1, len(resources))

    @cassette_name('firewall')
    def test_firewall_rules_not_equal(self):
        p = self.load_policy({
            'name': 'test-azure-sql-server',
            'resource': 'azure.sqlserver',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctestsqlserver*'},
                {'type': 'firewall-rules',
                 'equal': ['0.0.0.0-0.0.0.1', '0.0.0.0-0.0.0.0', '1.2.2.128/25']}],
        }, validate=True)
        resources = p.run()
        self.assertEqual(0, len(resources))

    @cassette_name('firewall')
    def test_firewall_bypass(self):
        p = self.load_policy({
            'name': 'test-azure-sql-server',
            'resource': 'azure.sqlserver',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctestsqlserver*'},
                {'type': 'firewall-bypass',
                 'mode': 'equal',
                 'list': ['AzureServices']}],
        })
        resources = p.run()
        self.assertEqual(1, len(resources))


class SQLServerFirewallFilterTest(BaseTest):

    resource = {'name': 'test', 'resourceGroup': 'test'}

    def test_query_empty_rules(self):
        rules = []
        expected = IPSet()
        self.assertEqual(expected, self._get_filter(rules)._query_rules(self.resource))

    def test_query_regular_rules(self):
        rules = [IpRange(start_ip_address='10.0.0.0', end_ip_address='10.0.255.255'),
                 IpRange(start_ip_address='8.8.8.8', end_ip_address='8.8.8.8')]
        expected = IPSet(['8.8.8.8', '10.0.0.0/16'])
        self.assertEqual(expected, self._get_filter(rules)._query_rules(self.resource))

    def test_query_regular_rules_with_magic(self):
        rules = [IpRange(start_ip_address='10.0.0.0', end_ip_address='10.0.255.255'),
                 IpRange(start_ip_address='8.8.8.8', end_ip_address='8.8.8.8'),
                 IpRange(start_ip_address='0.0.0.0', end_ip_address='0.0.0.0')]
        expected = IPSet(['8.8.8.8', '10.0.0.0/16'])
        self.assertEqual(expected, self._get_filter(rules)._query_rules(self.resource))

    def _get_filter(self, rules, mode='equal'):
        data = {mode: ['10.0.0.0/8', '127.0.0.1']}
        filter = SqlServerFirewallRulesFilter(data, Mock())
        filter.client = Mock()
        filter.client.firewall_rules.list_by_server.return_value = rules
        return filter


class SqlServerFirewallBypassFilterTest(BaseTest):

    resource = {'name': 'test', 'resourceGroup': 'test'}

    scenarios = [
        [[], []],
        [[IpRange(start_ip_address='10.0.0.0', end_ip_address='10.0.255.255'),
          IpRange(start_ip_address='8.8.8.8', end_ip_address='8.8.8.8')], []],
        [[IpRange(start_ip_address='10.0.0.0', end_ip_address='10.0.255.255'),
          IpRange(start_ip_address='8.8.8.8', end_ip_address='8.8.8.8'),
         IpRange(start_ip_address='0.0.0.0', end_ip_address='0.0.0.0')], ['AzureServices']],
    ]

    @parameterized.expand(scenarios)
    def test_run(self, rules, expected):
        f = SqlServerFirewallBypassFilter({'mode': 'equal', 'list': []}, Mock())
        f.client = Mock()
        f.client.firewall_rules.list_by_server.return_value = rules
        self.assertEqual(expected, f._query_bypass(self.resource))


class SQLServerFirewallActionTest(BaseTest):

    scenarios = [
        # ip rules, bypass rules, append, expected add, expected remove

        # Replace, no bypass
        ['replace', ['0.0.0.0/1', '11.12.13.14', '21.22.23.24'], None, False,
         ['0.0.0.0/1', '11.12.13.14', '21.22.23.24'], ['1.2.2.128s25']],

        # Replace, empty bypass
        ['replace-empty-bypass', ['0.0.0.0/1', '10.0.0.0-10.0.255.255', '21.22.23.24'], [], False,
         ['0.0.0.0/1', '10.0.0.0/16', '21.22.23.24'], ['1.2.2.128s25', 'AllowAllWindowsAzureIps']],

        # Append new rules, no bypass
        ['append', ['0.0.0.0/1', '11.12.13.14', '21.22.23.24'], None, True,
         ['0.0.0.0/1', '11.12.13.14', '21.22.23.24'], []],

        # Append new rules, empty bypass
        ['append-empty-bypass', ['0.0.0.0/1', '11.12.13.14', '21.22.23.24'], [], True,
         ['0.0.0.0/1', '11.12.13.14', '21.22.23.24'], []],

        # Remove all
        ['remove-all', [], [], False,
         [], ['1.2.2.128s25', 'AllowAllWindowsAzureIps']],

        # Only bypass
        ['only-bypass', [], ['AzureServices'], False,
         [], ['1.2.2.128s25']],

        # Append bypass
        ['append-bypass', [], ['AzureServices'], True,
         [], []],
    ]

    @parameterized.expand(scenarios)
    @patch('azure.mgmt.sql.operations._firewall_rules_operations.'
           'FirewallRulesOperations.create_or_update')
    @patch('azure.mgmt.sql.operations._firewall_rules_operations.'
           'FirewallRulesOperations.delete')
    @cassette_name('firewall_action')
    @arm_template('sqlserver.json')
    def test_action_policy(self, name, ip_rules, bypass_rules, append, expected_add,
                           expected_remove, delete, update):
        template = {
            'name': 'test-azure-sql-server',
            'resource': 'azure.sqlserver',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctestsqlserver*'}],
            'actions': [
                {'type': 'set-firewall-rules',
                 'append': append}]}

        if bypass_rules is not None:
            template['actions'][0]['bypass-rules'] = bypass_rules

        if ip_rules is not None:
            template['actions'][0]['ip-rules'] = ip_rules

        p = self.load_policy(template)
        resources = p.run()
        self.assertEqual(1, len(resources))

        # Added IP's
        added = IPSet()
        for r in [IPRange(args[3], args[4]) for _, args, _ in update.mock_calls]:
            added.add(r)

        self.assertEqual(IPSet(expected_add), added)

        # Removed IP's
        self.assertEqual(set(expected_remove), set([args[2] for _, args, _ in delete.mock_calls]))

    @patch('azure.mgmt.sql.operations._firewall_rules_operations.'
           'FirewallRulesOperations.create_or_update')
    @cassette_name('firewall_action')
    @arm_template('sqlserver.json')
    def test_action_prefix(self, update):
        template = {
            'name': 'test-azure-sql-server',
            'resource': 'azure.sqlserver',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctestsqlserver*'}],
            'actions': [
                {'type': 'set-firewall-rules',
                 'ip-rules': ['11.12.13.111'],
                 'prefix': 'test-prefix'}]}

        p = self.load_policy(template)
        resources = p.run()
        self.assertEqual(1, len(resources))

        _, args, _ = update.mock_calls[0]
        self.assertIn("test-prefix", args[2])
