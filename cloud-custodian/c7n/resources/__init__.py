# Copyright 2015-2017 Capital One Services, LLC
# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#
# AWS resources to manage
#
from __future__ import absolute_import, division, print_function, unicode_literals

from c7n.provider import clouds

LOADED = set()


def load_resources(resource_types=('*',)):
    pmap = {}
    for r in resource_types:
        parts = r.split('.', 1)
        pmap.setdefault(parts[0], []).append(r)

    load_providers(set(pmap))
    missing = []
    for pname, p in clouds.items():
        if '*' in pmap:
            p.get_resource_types(('*',))
        elif pname in pmap:
            _, not_found = p.get_resource_types(pmap[pname])
            missing.extend(not_found)
    return missing


def should_load_provider(name, provider_types):
    global LOADED
    if (name not in LOADED and
        ('*' in provider_types or
         name in provider_types)):
        return True
    return False


def load_providers(provider_types):
    global LOADED

    # Even though we're lazy loading resources we still need to import
    # those that are making available generic filters/actions
    if should_load_provider('aws', provider_types):
        import c7n.resources.securityhub
        import c7n.resources.sfn
        import c7n.resources.ssm # NOQA

    if should_load_provider('azure', provider_types):
        from c7n_azure.entry import initialize_azure
        initialize_azure()

    if should_load_provider('gcp', provider_types):
        from c7n_gcp.entry import initialize_gcp
        initialize_gcp()

    if should_load_provider('k8s', provider_types):
        from c7n_kube.entry import initialize_kube
        initialize_kube()

    LOADED.update(provider_types)
