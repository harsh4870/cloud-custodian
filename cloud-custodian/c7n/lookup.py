# Copyright 2019 Microsoft Corporation
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

import jmespath
import copy


class Lookup(object):
    RESOURCE_SOURCE = 'resource'

    schema = {
        'type': 'object',
        'oneOf': [
            {
                'properties': {
                    'type': {'type': 'string', 'enum': [RESOURCE_SOURCE]},
                    'key': {'type': 'string'}
                },
                'additionalProperties': False,
                'required': ['type', 'key']
            }
        ]
    }

    @staticmethod
    def lookup_type(schema):
        lookup_schema = copy.deepcopy(Lookup.schema)
        for lookup in lookup_schema['oneOf']:
            lookup['properties']['default-value'] = schema

        return {
            'oneOf': [
                lookup_schema,
                schema
            ]
        }

    @staticmethod
    def extract(source, data=None):
        if Lookup.is_lookup(source):
            return Lookup.get_value(source, data)
        else:
            return source

    @staticmethod
    def is_lookup(source):
        return type(source) is dict

    @staticmethod
    def get_value(source, data=None):
        if source['type'] == Lookup.RESOURCE_SOURCE:
            return Lookup.get_value_from_resource(source, data)

    @staticmethod
    def get_value_from_resource(source, resource):
        value = jmespath.search(source['key'], resource)

        if value is not None:
            return value
        if 'default-value' not in source:
            raise Exception('Lookup for key, {}, returned None'.format(source['key']))
        else:
            return source['default-value']
