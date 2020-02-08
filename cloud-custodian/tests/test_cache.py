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

from unittest import TestCase
from c7n import cache, config
from argparse import Namespace
from six.moves import cPickle as pickle
import tempfile
import mock
import os


class TestCache(TestCase):

    def test_factory(self):
        self.assertIsInstance(cache.factory(None), cache.NullCache)
        test_config = Namespace(cache_period=60, cache="test-cloud-custodian.cache")
        self.assertIsInstance(cache.factory(test_config), cache.FileCacheManager)
        test_config.cache = None
        self.assertIsInstance(cache.factory(test_config), cache.NullCache)


class MemCacheTest(TestCase):

    def test_mem_factory(self):
        self.assertEqual(
            cache.factory(config.Bag(cache='memory', cache_period=5)).__class__,
            cache.InMemoryCache)

    def test_get_set(self):
        mem_cache = cache.InMemoryCache()
        mem_cache.save({'region': 'us-east-1'}, {'hello': 'world'})
        self.assertEqual(mem_cache.size(), 1)
        self.assertEqual(mem_cache.load(), True)

        mem_cache = cache.InMemoryCache()
        self.assertEqual(
            mem_cache.get({'region': 'us-east-1'}),
            {'hello': 'world'})


class FileCacheManagerTest(TestCase):

    def setUp(self):
        self.test_config = Namespace(
            cache_period=60, cache="test-cloud-custodian.cache"
        )
        self.test_cache = cache.FileCacheManager(self.test_config)
        self.test_key = "test"
        self.bad_key = "bad"
        self.test_value = [1, 2, 3]

    def test_get_set(self):
        t = self.temporary_file_with_cleanup()
        c = cache.FileCacheManager(Namespace(cache_period=60, cache=t.name))
        self.assertFalse(c.load())
        k1 = {"account": "12345678901234", "region": "us-west-2", "resource": "ec2"}
        c.save(k1, range(5))
        self.assertEqual(c.get(k1), range(5))
        k2 = {"account": "98765432101234", "region": "eu-west-1", "resource": "asg"}
        c.save(k2, range(2))
        self.assertEqual(c.get(k1), range(5))
        self.assertEqual(c.get(k2), range(2))

        c2 = cache.FileCacheManager(Namespace(cache_period=60, cache=t.name))
        self.assertTrue(c2.load())
        self.assertEqual(c2.get(k1), range(5))
        self.assertEqual(c2.get(k2), range(2))

    def test_get(self):
        # mock the pick and set it to the data variable
        test_pickle = pickle.dumps(
            {pickle.dumps(self.test_key): self.test_value}, protocol=2
        )
        self.test_cache.data = pickle.loads(test_pickle)

        # assert
        self.assertEqual(self.test_cache.get(self.test_key), self.test_value)
        self.assertEqual(self.test_cache.get(self.bad_key), None)

    def test_load(self):
        t = self.temporary_file_with_cleanup(suffix=".cache")

        load_config = Namespace(cache_period=0, cache=t.name)
        load_cache = cache.FileCacheManager(load_config)
        self.assertFalse(load_cache.load())
        load_cache.data = {"key": "value"}
        self.assertTrue(load_cache.load())

    @mock.patch.object(cache.os, "makedirs")
    @mock.patch.object(cache.os.path, "exists")
    @mock.patch.object(cache.pickle, "dump")
    @mock.patch.object(cache.pickle, "dumps")
    def test_save_exists(self, mock_dumps, mock_dump, mock_exists, mock_mkdir):
        # path exists then we dont need to create the folder
        mock_exists.return_value = True
        # tempfile to hold the pickle
        temp_cache_file = self.temporary_file_with_cleanup()

        self.test_cache.cache_path = temp_cache_file.name
        # make the call
        self.test_cache.save(self.test_key, self.test_value)

        # assert if file already exists
        self.assertFalse(mock_mkdir.called)
        self.assertTrue(mock_dumps.called)
        self.assertTrue(mock_dump.called)

        # mkdir should NOT be called, but pickles should
        self.assertEqual(mock_mkdir.call_count, 0)
        self.assertEqual(mock_dump.call_count, 1)
        self.assertEqual(mock_dumps.call_count, 1)

    @mock.patch.object(cache.os, "makedirs")
    @mock.patch.object(cache.os.path, "exists")
    @mock.patch.object(cache.pickle, "dump")
    @mock.patch.object(cache.pickle, "dumps")
    def test_save_doesnt_exists(self, mock_dumps, mock_dump, mock_exists, mock_mkdir):
        temp_cache_file = self.temporary_file_with_cleanup()

        self.test_cache.cache_path = temp_cache_file.name

        # path doesnt exists then we will create the folder
        # raise some sort of exception in the try
        mock_exists.return_value = False
        mock_dump.side_effect = Exception("Error")
        mock_mkdir.side_effect = Exception("Error")

        # make the call
        self.test_cache.save(self.test_key, self.test_value)

        # assert if file doesnt exists
        self.assertTrue(mock_mkdir.called)
        self.assertTrue(mock_dumps.called)
        self.assertTrue(mock_dump.called)

        # all 3 should be called once
        self.assertEqual(mock_mkdir.call_count, 1)
        self.assertEqual(mock_dump.call_count, 1)
        self.assertEqual(mock_dumps.call_count, 1)

    def temporary_file_with_cleanup(self, **kwargs):
        """
        NamedTemporaryFile with delete=True has
        significantly different behavior on Windows
        so we utilize delete=False to simplify maintaining
        compatibility.
        """
        t = tempfile.NamedTemporaryFile(delete=False, **kwargs)

        self.addCleanup(os.unlink, t.name)
        self.addCleanup(t.close)
        return t
