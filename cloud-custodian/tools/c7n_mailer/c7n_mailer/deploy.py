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

import copy
import logging
import json
import os

from c7n.mu import (
    CloudWatchEventSource,
    LambdaFunction,
    LambdaManager,
    PythonPackageArchive)


log = logging.getLogger('custodian-mailer')

entry_source = """\
import logging

from c7n_mailer import handle

logger = logging.getLogger('custodian.mailer')
log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=log_format)
logging.getLogger('botocore').setLevel(logging.WARNING)

def dispatch(event, context):
    return handle.start_c7n_mailer(logger)
"""


def get_archive(config):
    archive = PythonPackageArchive(modules=[
        'c7n_mailer',
        # core deps
        'jinja2', 'markupsafe', 'ruamel', 'ldap3', 'pyasn1', 'redis',
        # for other dependencies
        'pkg_resources',
        # transport datadog - recursive deps
        'datadog', 'simplejson', 'decorator',
        # requests (recursive deps), needed by datadog, slackclient, splunk
        'requests', 'urllib3', 'idna', 'chardet', 'certifi',
        # used by splunk; also dependencies of c7n itself
        'jsonpointer', 'jsonpatch'])

    for d in set(config['templates_folders']):
        if not os.path.exists(d):
            continue
        for t in [f for f in os.listdir(d) if os.path.splitext(f)[1] == '.j2']:
            with open(os.path.join(d, t)) as fh:
                archive.add_contents('msg-templates/%s' % t, fh.read())

    function_config = copy.deepcopy(config)
    function_config['templates_folders'] = ['msg-templates/']
    archive.add_contents('config.json', json.dumps(function_config))
    archive.add_contents('periodic.py', entry_source)

    archive.close()
    return archive


def provision(config, session_factory):
    func_config = dict(
        name=config.get('lambda_name', 'cloud-custodian-mailer'),
        description=config.get('lambda_description', 'Cloud Custodian Mailer'),
        tags=config.get('lambda_tags', {}),
        handler='periodic.dispatch',
        runtime=config['runtime'],
        memory_size=config['memory'],
        timeout=config['timeout'],
        role=config['role'],
        subnets=config['subnets'],
        security_groups=config['security_groups'],
        dead_letter_config=config.get('dead_letter_config', {}),
        events=[
            CloudWatchEventSource(
                {'type': 'periodic',
                 'schedule': config.get('lambda_schedule', 'rate(5 minutes)')},
                session_factory)
        ])

    archive = get_archive(config)
    func = LambdaFunction(func_config, archive)
    log.info("Provisioning mailer lambda %s" % (session_factory().region_name))
    manager = LambdaManager(session_factory)
    manager.publish(func)
