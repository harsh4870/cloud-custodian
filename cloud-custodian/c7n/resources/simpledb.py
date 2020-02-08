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

import itertools

from c7n.actions import Action
from c7n.manager import resources
from c7n.query import QueryResourceManager, TypeInfo
from c7n.utils import local_session, chunks, type_schema


@resources.register('simpledb')
class SimpleDB(QueryResourceManager):

    class resource_type(TypeInfo):
        service = "sdb"
        enum_spec = ("list_domains", "DomainNames", None)
        id = name = "DomainName"
        arn_type = "domain"

    permissions = ('sdb:DomainMetadata',)

    def augment(self, resources):
        def _augment(resource_set):
            client = local_session(self.session_factory).client('sdb')
            results = []
            for r in resources:
                info = client.domain_metadata(DomainName=r)
                info.pop('ResponseMetadata')
                info['DomainName'] = r
                results.append(info)
            return results

        with self.executor_factory(max_workers=3) as w:
            return list(itertools.chain(
                *w.map(_augment, chunks(resources, 20))))


@SimpleDB.action_registry.register('delete')
class Delete(Action):

    schema = type_schema('delete')
    permissions = ('sdb:DeleteDomain',)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('sdb')
        for r in resources:
            client.delete_domain(DomainName=r['DomainName'])
