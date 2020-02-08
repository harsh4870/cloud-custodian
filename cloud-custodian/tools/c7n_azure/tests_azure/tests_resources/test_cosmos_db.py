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
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)

from azure.cosmos.cosmos_client import CosmosClient
from ..azure_common import BaseTest, arm_template, cassette_name
from c7n_azure.resources.cosmos_db import (CosmosDBChildResource, CosmosDBFirewallRulesFilter,
                                           CosmosFirewallBypassFilter,
                                           PORTAL_IPS, AZURE_CLOUD_IPS, THROUGHPUT_MULTIPLIER)
from c7n_azure.session import Session
from mock import patch, Mock
from netaddr import IPSet
from parameterized import parameterized

from c7n.utils import local_session


class CosmosDBTest(BaseTest):

    def setUp(self):
        super(CosmosDBTest, self).setUp()

    def test_cosmos_db_schema_validate(self):
        with self.sign_out_patch():
            p = self.load_policy({
                'name': 'test-azure-cosmos-db',
                'resource': 'azure.cosmosdb'
            }, validate=True)
            self.assertTrue(p)

            p = self.load_policy({
                'name': 'test-azure-cosmos-db',
                'resource': 'azure.cosmosdb-database'
            }, validate=True)
            self.assertTrue(p)

            p = self.load_policy({
                'name': 'test-azure-cosmos-db',
                'resource': 'azure.cosmosdb-collection'
            }, validate=True)
            self.assertTrue(p)

            p = self.load_policy({
                'name': 'test-azure-cosmosdb',
                'resource': 'azure.cosmosdb',
                'filters': [
                    {'type': 'value',
                     'key': 'name',
                     'op': 'glob',
                     'value_type': 'normalize',
                     'value': 'cctestcosmosdb*'}],
                'actions': [
                    {'type': 'set-firewall-rules',
                     'bypass-rules': ['Portal'],
                     'ip-rules': ['0.0.0.0/1', '11.12.13.14', '21.22.23.24']
                     }
                ]
            }, validate=True)
            self.assertTrue(p)

    @arm_template('cosmosdb.json')
    def test_find_by_name(self):
        p = self.load_policy({
            'name': 'test-azure-cosmosdb',
            'resource': 'azure.cosmosdb',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctestcosmosdb*'}],
        })
        resources = p.run()
        self.assertEqual(len(resources), 1)

    @arm_template('cosmosdb.json')
    def test_find_by_name_database(self):
        p = self.load_policy({
            'name': 'test-azure-cosmosdb',
            'resource': 'azure.cosmosdb-database',
            'filters': [
                {'type': 'value',
                 'key': 'id',
                 'op': 'eq',
                 'value_type': 'normalize',
                 'value': 'cctestcdatabase'}],
        })
        resources = p.run()
        self.assertEqual(len(resources), 1)

    @arm_template('cosmosdb.json')
    def test_find_by_name_collection(self):
        p = self.load_policy({
            'name': 'test-azure-cosmosdb',
            'resource': 'azure.cosmosdb-collection',
            'filters': [
                {'type': 'value',
                 'key': 'id',
                 'op': 'eq',
                 'value_type': 'normalize',
                 'value': 'cccontainer'}],
        })
        resources = p.run()
        self.assertEqual(len(resources), 1)

    @arm_template('cosmosdb.json')
    def test_collection_metrics_filter(self):
        p = self.load_policy({
            'name': 'test-azure-cosmosdb',
            'resource': 'azure.cosmosdb-collection',
            'filters': [
                {'type': 'value',
                 'key': 'id',
                 'op': 'eq',
                 'value_type': 'normalize',
                 'value': 'cccontainer'},
                {'type': 'metric',
                 'metric': 'ProvisionedThroughput',
                 'op': 'le',
                 'aggregation': 'average',
                 'interval': 'PT5M',
                 'threshold': 1000}
            ]
        }, validate=True)
        resources = p.run()
        self.assertEqual(len(resources), 1)

    @arm_template('cosmosdb.json')
    def test_database_metrics_filter(self):
        p = self.load_policy({
            'name': 'test-azure-cosmosdb',
            'resource': 'azure.cosmosdb-database',
            'filters': [
                {'type': 'value',
                 'key': 'id',
                 'op': 'eq',
                 'value_type': 'normalize',
                 'value': 'cctestcdatabase'},
                {'type': 'metric',
                 'metric': 'ProvisionedThroughput',
                 'op': 'le',
                 'aggregation': 'average',
                 'interval': 'PT5M',
                 'threshold': 1000}
            ]
        }, validate=True)
        resources = p.run()
        self.assertEqual(len(resources), 1)

    @arm_template('cosmosdb.json')
    @cassette_name('firewall')
    def test_firewall_rules_include(self):
        p = self.load_policy({
            'name': 'test-azure-cosmosdb',
            'resource': 'azure.cosmosdb',
            'filters': [
                {'type': 'firewall-rules',
                 'include': ['3.1.1.1']}],
        }, validate=True)
        resources = p.run()
        self.assertEqual(1, len(resources))

    @arm_template('cosmosdb.json')
    @cassette_name('firewall')
    def test_firewall_rules_include_cidr(self):
        p = self.load_policy({
            'name': 'test-azure-cosmosdb',
            'resource': 'azure.cosmosdb',
            'filters': [
                {'type': 'firewall-rules',
                 'include': ['1.2.2.128/25']}],
        }, validate=True)
        resources = p.run()
        self.assertEqual(1, len(resources))

    @arm_template('cosmosdb.json')
    @cassette_name('firewall')
    def test_firewall_rules_not_equal(self):
        p = self.load_policy({
            'name': 'test-azure-cosmosdb',
            'resource': 'azure.cosmosdb',
            'filters': [
                {'type': 'firewall-rules',
                 'equal': ['1.0.0.0/1']}],
        }, validate=True)
        resources = p.run()
        self.assertEqual(0, len(resources))

    @arm_template('cosmosdb.json')
    @cassette_name('firewall')
    def test_firewall_bypass(self):
        p = self.load_policy({
            'name': 'test-azure-cosmosdb',
            'resource': 'azure.cosmosdb',
            'filters': [
                {'type': 'firewall-bypass',
                 'mode': 'equal',
                 'list': ['Portal']}]
        })
        resources = p.run()
        self.assertEqual(1, len(resources))

    @arm_template('cosmosdb.json')
    def test_offer_collection(self):
        p = self.load_policy({
            'name': 'test-azure-cosmosdb',
            'resource': 'azure.cosmosdb-collection',
            'filters': [
                {'type': 'offer',
                 'key': 'content.offerThroughput',
                 'op': 'gt',
                 'value': 100}],
        })
        resources = p.run()

        self.assertEqual(1, len(resources))
        self.assertEqual('Hash', resources[0]['partitionKey']['kind'])

    @arm_template('cosmosdb.json')
    def test_store_throughput_state_collection_action(self):
        p = self.load_policy({
            'name': 'test-azure-cosmosdb',
            'resource': 'azure.cosmosdb-collection',
            'filters': [
                {
                    'type': 'value',
                    'key': 'id',
                    'op': 'eq',
                    'value': 'cccontainer'
                }
            ],
            'actions': [
                {
                    'type': 'save-throughput-state',
                    'state-tag': 'test-store-throughput'
                }
            ]
        })

        collections = p.run()
        self.assertEqual(len(collections), 1)

        account_name = collections[0]['c7n:parent']['name']

        self.sleep_in_live_mode()

        client = local_session(Session).client(
            'azure.mgmt.cosmosdb.CosmosDBManagementClient')
        cosmos_account = client.database_accounts.get('test_cosmosdb', account_name)
        self.assertTrue('test-store-throughput' in cosmos_account.tags)

        tag_value = cosmos_account.tags['test-store-throughput']
        expected_throughput = collections[0]['c7n:offer']['content']['offerThroughput']
        expected_scaled_throughput = int(expected_throughput / THROUGHPUT_MULTIPLIER)
        expected_tag_value = '{}:{}'.format(collections[0]['_rid'], expected_scaled_throughput)
        self.assertEqual(expected_tag_value, tag_value)


class CosmosDBFirewallFilterTest(BaseTest):

    def test_query_firewall_disabled(self):
        resource = {'properties': {'ipRangeFilter': '', 'isVirtualNetworkFilterEnabled': False}}
        expected = IPSet(['0.0.0.0/0'])
        self.assertEqual(expected, self._get_filter()._query_rules(resource))

    def test_query_block_everything(self):
        resource = {'properties': {'ipRangeFilter': '', 'isVirtualNetworkFilterEnabled': True}}
        expected = IPSet()
        self.assertEqual(expected, self._get_filter()._query_rules(resource))

    def test_query_regular(self):
        resource = {'properties': {'ipRangeFilter': '10.0.0.0/16,8.8.8.8',
                                   'isVirtualNetworkFilterEnabled': False}}
        expected = IPSet(['10.0.0.0/16', '8.8.8.8'])
        self.assertEqual(expected, self._get_filter()._query_rules(resource))

    def test_query_regular_plus_portal(self):
        extra = ','.join(PORTAL_IPS)
        resource = {'properties': {'ipRangeFilter': extra + ',10.0.0.0/16,8.8.8.8',
                                   'isVirtualNetworkFilterEnabled': False}}
        expected = IPSet(['10.0.0.0/16', '8.8.8.8'])
        self.assertEqual(expected, self._get_filter()._query_rules(resource))

    def test_query_regular_plus_cloud(self):
        extra = ', '.join(AZURE_CLOUD_IPS)
        resource = {'properties': {'ipRangeFilter': extra + ',10.0.0.0/16,8.8.8.8',
                                   'isVirtualNetworkFilterEnabled': False}}
        expected = IPSet(['10.0.0.0/16', '8.8.8.8'])
        self.assertEqual(expected, self._get_filter()._query_rules(resource))

    def test_query_regular_plus_portal_cloud(self):
        extra = ','.join(PORTAL_IPS + AZURE_CLOUD_IPS)
        resource = {'properties': {'ipRangeFilter': extra + ',10.0.0.0/16,8.8.8.8',
                                   'isVirtualNetworkFilterEnabled': False}}
        expected = IPSet(['10.0.0.0/16', '8.8.8.8'])
        self.assertEqual(expected, self._get_filter()._query_rules(resource))

    def test_query_regular_plus_partial_cloud(self):
        extra = ','.join(PORTAL_IPS[1:])
        resource = {'properties': {'ipRangeFilter': extra + ',10.0.0.0/16,8.8.8.8',
                                   'isVirtualNetworkFilterEnabled': False}}
        expected = IPSet(['10.0.0.0/16', '8.8.8.8'] + PORTAL_IPS[1:])
        self.assertEqual(expected, self._get_filter()._query_rules(resource))

    def _get_filter(self, mode='equal'):
        data = {mode: ['10.0.0.0/8', '127.0.0.1']}
        return CosmosDBFirewallRulesFilter(data, Mock())


class CosmosDBFirewallBypassFilterTest(BaseTest):

    scenarios = [
        ['', False, ['AzureCloud', 'Portal']],
        ['', True, []],
        ['1.0.0.0', True, []],
        [','.join(AZURE_CLOUD_IPS), False, ['AzureCloud']],
        [','.join(PORTAL_IPS), False, ['Portal']],
        [','.join(AZURE_CLOUD_IPS + PORTAL_IPS), False, ['AzureCloud', 'Portal']],
        [','.join(AZURE_CLOUD_IPS + ['10.0.0.8']), False, ['AzureCloud']],
        [','.join(PORTAL_IPS + ['10.0.0.8']), False, ['Portal']],
        [','.join(AZURE_CLOUD_IPS + PORTAL_IPS + ['10.0.0.8']), False, ['AzureCloud', 'Portal']],
    ]

    @parameterized.expand(scenarios)
    def test_run(self, ip_range, vnet_filter_enabled, expected):
        resource = {'properties': {'ipRangeFilter': ip_range,
                                   'isVirtualNetworkFilterEnabled': vnet_filter_enabled}}
        f = CosmosFirewallBypassFilter({'mode': 'equal', 'list': []}, Mock())
        self.assertEqual(expected, f._query_bypass(resource))


class CosmosDBFirewallActionTest(BaseTest):

    @patch('azure.mgmt.cosmosdb.operations._database_accounts_operations.'
           'DatabaseAccountsOperations.create_or_update')
    @cassette_name('firewall_action')
    @arm_template('cosmosdb.json')
    def test_set_ip_range_filter_append(self, update_mock):
        p = self.load_policy({
            'name': 'test-azure-cosmosdb',
            'resource': 'azure.cosmosdb',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctestcosmosdb*'}],
            'actions': [
                {'type': 'set-firewall-rules',
                 'ip-rules': ['0.0.0.0/1', '11.12.13.14', '21.22.23.24']
                 }
            ]
        })
        resources = p.run()
        self.assertEqual(len(resources), 1)

        self.assertEqual(1, len(update_mock.mock_calls))
        name, args, kwargs = update_mock.mock_calls[0]

        self.assertEqual(resources[0]['resourceGroup'], args[0])
        self.assertEqual(resources[0]['name'], args[1])
        self.assertEqual(
            set('0.0.0.0/1,128.0.0.0/1,11.12.13.14,21.22.23.24,'
                '104.42.195.92,40.76.54.131,52.176.6.30,52.169.50.45,52.187.184.26'.split(',')),
            set(kwargs['create_update_parameters']['properties']['ipRangeFilter'].split(',')))

    @patch('azure.mgmt.cosmosdb.operations._database_accounts_operations.'
           'DatabaseAccountsOperations.create_or_update')
    @cassette_name('firewall_action')
    @arm_template('cosmosdb.json')
    def test_set_ip_range_filter_replace(self, update_mock):
        p = self.load_policy({
            'name': 'test-azure-cosmosdb',
            'resource': 'azure.cosmosdb',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctestcosmosdb*'}],
            'actions': [
                {'type': 'set-firewall-rules',
                 'append': False,
                 'ip-rules': ['0.0.0.0/1', '11.12.13.14', '21.22.23.24']
                 }
            ]
        })
        resources = p.run()
        self.assertEqual(len(resources), 1)

        self.assertEqual(1, len(update_mock.mock_calls))
        name, args, kwargs = update_mock.mock_calls[0]

        self.assertEqual(resources[0]['resourceGroup'], args[0])
        self.assertEqual(resources[0]['name'], args[1])
        self.assertEqual(
            set('0.0.0.0/1,11.12.13.14,21.22.23.24,104.42.195.92,40.76.54.131,'
                '52.176.6.30,52.169.50.45,52.187.184.26'.split(',')),
            set(kwargs['create_update_parameters']['properties']['ipRangeFilter'].split(',')))

    @patch('azure.mgmt.cosmosdb.operations._database_accounts_operations.'
           'DatabaseAccountsOperations.create_or_update')
    @cassette_name('firewall_action')
    @arm_template('cosmosdb.json')
    def test_set_ip_range_filter_replace_bypass(self, update_mock):
        p = self.load_policy({
            'name': 'test-azure-cosmosdb',
            'resource': 'azure.cosmosdb',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctestcosmosdb*'}],
            'actions': [
                {'type': 'set-firewall-rules',
                 'append': False,
                 'bypass-rules': ['Portal', 'AzureCloud'],
                 'ip-rules': ['0.0.0.0/1', '11.12.13.14', '21.22.23.24']
                 }
            ]
        })
        resources = p.run()
        self.assertEqual(len(resources), 1)

        self.assertEqual(1, len(update_mock.mock_calls))
        name, args, kwargs = update_mock.mock_calls[0]

        self.assertEqual(resources[0]['resourceGroup'], args[0])
        self.assertEqual(resources[0]['name'], args[1])
        self.assertEqual(
            {'0.0.0.0/1',
             '104.42.195.92',
             '11.12.13.14',
             '21.22.23.24',
             '40.76.54.131',
             '52.169.50.45',
             '52.176.6.30',
             '52.187.184.26',
             '0.0.0.0'
             },
            set(kwargs['create_update_parameters']['properties']['ipRangeFilter'].split(',')))

    @patch('azure.mgmt.cosmosdb.operations._database_accounts_operations.'
           'DatabaseAccountsOperations.create_or_update')
    @cassette_name('firewall_action')
    @arm_template('cosmosdb.json')
    def test_set_ip_range_filter_remove_bypass(self, update_mock):
        p = self.load_policy({
            'name': 'test-azure-cosmosdb',
            'resource': 'azure.cosmosdb',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctestcosmosdb*'}],
            'actions': [
                {'type': 'set-firewall-rules',
                 'append': False,
                 'bypass-rules': [],
                 'ip-rules': ['21.22.23.24']
                 }
            ]
        })
        resources = p.run()
        self.assertEqual(len(resources), 1)

        self.assertEqual(1, len(update_mock.mock_calls))
        name, args, kwargs = update_mock.mock_calls[0]

        self.assertEqual(resources[0]['resourceGroup'], args[0])
        self.assertEqual(resources[0]['name'], args[1])
        self.assertEqual(
            {'21.22.23.24'},
            set(kwargs['create_update_parameters']['properties']['ipRangeFilter'].split(',')))

    @patch('azure.mgmt.cosmosdb.operations._database_accounts_operations.'
           'DatabaseAccountsOperations.create_or_update')
    @cassette_name('firewall_action')
    @arm_template('cosmosdb.json')
    def test_set_vnet_append(self, update_mock):
        p = self.load_policy({
            'name': 'test-azure-cosmosdb',
            'resource': 'azure.cosmosdb',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctestcosmosdb*'}],
            'actions': [
                {'type': 'set-firewall-rules',
                 'append': True,
                 'virtual-network-rules': ['id1', 'id2'],
                 'ip-rules': ['0.0.0.0/1', '11.12.13.14', '21.22.23.24']
                 }
            ]
        })
        resources = p.run()
        self.assertEqual(len(resources), 1)

        name, args, kwargs = update_mock.mock_calls[0]

        self.assertEqual(resources[0]['resourceGroup'], args[0])
        self.assertEqual(resources[0]['name'], args[1])
        self.assertEqual(
            set('0.0.0.0/1,128.0.0.0/1,11.12.13.14,21.22.23.24,'
                '104.42.195.92,40.76.54.131,52.176.6.30,52.169.50.45,52.187.184.26'.split(',')),
            set(kwargs['create_update_parameters']['properties']['ipRangeFilter'].split(',')))
        self.assertEqual(
            {'id1', 'id2'},
            set([r.id for r in
                 kwargs['create_update_parameters']['properties']['virtualNetworkRules']]))


class CosmosDBThroughputActionsTest(BaseTest):
    def setUp(self, *args, **kwargs):
        super(CosmosDBThroughputActionsTest, self).setUp(*args, **kwargs)
        self.client = local_session(Session).client(
            'azure.mgmt.cosmosdb.CosmosDBManagementClient')
        sub_id = local_session(Session).get_subscription_id()[-12:]
        account_name = "cctestcosmosdb%s" % sub_id
        key = CosmosDBChildResource.get_cosmos_key(
            'test_cosmosdb', account_name, self.client, readonly=False)
        self.data_client = CosmosClient(
            url_connection='https://%s.documents.azure.com:443/' % account_name,
            auth={
                'masterKey': key
            }
        )
        self.offer = None

    def tearDown(self, *args, **kwargs):
        super(CosmosDBThroughputActionsTest, self).tearDown(*args, **kwargs)
        if self.offer:
            self.offer['content']['offerThroughput'] = 400
            self.data_client.ReplaceOffer(
                self.offer['_self'],
                self.offer
            )

    def test_replace_offer_collection_action(self):
        p = self.load_policy({
            'name': 'test-azure-cosmosdb',
            'resource': 'azure.cosmosdb-collection',
            'filters': [
                {
                    'type': 'value',
                    'key': 'id',
                    'op': 'eq',
                    'value': 'cccontainer'
                },
                {
                    'type': 'offer',
                    'key': 'content.offerThroughput',
                    'op': 'eq',
                    'value': 400
                }
            ],
            'actions': [
                {
                    'type': 'replace-offer',
                    'throughput': 500
                }
            ]
        })
        collections = p.run()
        self.offer = collections[0]['c7n:offer']

        self.assertEqual(len(collections), 1)
        self._assert_offer_throughput_equals(500, collections[0]['_self'])

    def test_restore_throughput_state_updates_throughput_from_tag(self):

        p1 = self.load_policy({
            'name': 'test-azure-cosmosdb',
            'resource': 'azure.cosmosdb-collection',
            'filters': [
                {
                    'type': 'value',
                    'key': 'id',
                    'op': 'eq',
                    'value': 'cccontainer'
                }
            ],
            'actions': [
                {
                    'type': 'save-throughput-state',
                    'state-tag': 'test-restore-throughput'
                }
            ]
        })

        collections = p1.run()
        self.assertEqual(len(collections), 1)

        collection_offer = collections[0]['c7n:offer']
        self.offer = collection_offer

        throughput_to_restore = collection_offer['content']['offerThroughput']

        collection_offer['content']['offerThroughput'] = throughput_to_restore + 100

        self.data_client.ReplaceOffer(
            collection_offer['_self'],
            collection_offer
        )

        self._assert_offer_throughput_equals(throughput_to_restore + 100, collections[0]['_self'])

        p2 = self.load_policy({
            'name': 'test-azure-cosmosdb',
            'resource': 'azure.cosmosdb-collection',
            'filters': [
                {
                    'type': 'value',
                    'key': 'id',
                    'op': 'eq',
                    'value': 'cccontainer'
                },
            ],
            'actions': [
                {
                    'type': 'restore-throughput-state',
                    'state-tag': 'test-restore-throughput'
                }
            ]
        })

        collections = p2.run()

        self.assertEqual(len(collections), 1)
        self._assert_offer_throughput_equals(throughput_to_restore, collections[0]['_self'])

    def _assert_offer_throughput_equals(self, throughput, resource_self):
        self.sleep_in_live_mode()
        offers = self.data_client.ReadOffers()
        offer = next((o for o in offers if o['resource'] == resource_self), None)
        self.assertIsNotNone(offer)
        self.assertEqual(throughput, offer['content']['offerThroughput'])
