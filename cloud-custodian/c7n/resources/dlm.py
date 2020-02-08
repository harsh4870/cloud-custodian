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
from __future__ import absolute_import, division, print_function, unicode_literals

from c7n.manager import resources
from c7n.query import QueryResourceManager, TypeInfo


@resources.register('dlm-policy')
class DLMPolicy(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'dlm'
        id = name = 'PolicyId'
        enum_spec = (
            'get_lifecycle_policies', 'Policies', None)
        detail_spec = ('get_lifecycle_policy', 'PolicyId', 'PolicyId', 'Policy')
        filter_name = 'PolicyIds'
        filter_type = 'list'
        arn = False
