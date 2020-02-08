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

import abc
import six
import importlib

from c7n.registry import PluginRegistry


clouds = PluginRegistry('c7n.providers')


@six.add_metaclass(abc.ABCMeta)
class Provider(object):
    """Provider Base Class"""

    @abc.abstractproperty
    def display_name(self):
        """display name for the provider in docs"""

    @abc.abstractproperty
    def resources(self):
        """resources registry for this cloud provider"""

    @abc.abstractproperty
    def resource_prefix(self):
        """resource prefix for this cloud provider in policy files."""

    @abc.abstractproperty
    def resource_map(self):
        """resource qualified name to python dotted path mapping."""

    @abc.abstractmethod
    def initialize(self, options):
        """Perform any provider specific initialization
        """

    @abc.abstractmethod
    def initialize_policies(self, policy_collection, options):
        """Perform any initialization of policies.

        Common usage is expanding policy collection for per
        region execution and filtering policies for applicable regions.
        """

    @abc.abstractmethod
    def get_session_factory(self, options):
        """Get a credential/session factory for api usage."""

    @classmethod
    def get_resource_types(cls, resource_types):
        """Return the resource classes for the given type names"""
        return import_resource_classes(cls.resource_map, resource_types)


def import_resource_classes(resource_map, resource_types):
    if '*' in resource_types:
        resource_types = list(resource_map)

    mod_map = {}
    rmods = set()
    not_found = []

    for r in resource_types:
        if r not in resource_map:
            not_found.append(r)
            continue
        rmodule, rclass = resource_map[r].rsplit('.', 1)
        rmods.add(rmodule)

    for rmodule in rmods:
        mod_map[rmodule] = importlib.import_module(rmodule)

    return [getattr(mod_map[rmodule], rclass, None) for
            rmodule, rclass in [
                resource_map[r].rsplit('.', 1) for r in resource_types
                if r in resource_map]], not_found


# nosetests seems to think this function is a test
import_resource_classes.__test__ = False


def resources(cloud_provider=None):
    results = {}
    for cname, ctype in clouds.items():
        if cloud_provider and cname != cloud_provider:
            continue
        for rname, rtype in ctype.resources.items():
            results['%s.%s' % (cname, rname)] = rtype
    return results


def get_resource_class(resource_type):
    if '.' in resource_type:
        provider_name, resource = resource_type.split('.', 1)
    else:
        provider_name, resource = 'aws', resource_type

    provider = clouds.get(provider_name)
    if provider is None:
        raise KeyError(
            "Invalid cloud provider: %s" % provider_name)

    factory = provider.resources.get(resource)
    if factory is None:
        raise KeyError("Invalid resource: %s for provider: %s" % (
            resource, provider_name))
    return factory
