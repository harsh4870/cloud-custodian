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
"""
Actions to take on resources
"""
from __future__ import absolute_import, division, print_function, unicode_literals

import logging

from c7n.exceptions import PolicyValidationError, ClientError
from c7n.executor import ThreadPoolExecutor
from c7n.registry import PluginRegistry


class ActionRegistry(PluginRegistry):

    def __init__(self, *args, **kw):
        super(ActionRegistry, self).__init__(*args, **kw)
        # Defer to provider initialization of registry
        from .notify import Notify
        from .webhook import Webhook
        self.register('notify', Notify)
        self.register('webhook', Webhook)

    def parse(self, data, manager):
        results = []
        for d in data:
            results.append(self.factory(d, manager))
        return results

    def factory(self, data, manager):
        if isinstance(data, dict):
            action_type = data.get('type')
            if action_type is None:
                raise PolicyValidationError(
                    "Invalid action type found in %s" % (data))
        else:
            action_type = data
            data = {}

        action_class = self.get(action_type)
        if action_class is None:
            raise PolicyValidationError(
                "Invalid action type %s, valid actions %s" % (
                    action_type, list(self.keys())))
        # Construct a ResourceManager
        return action_class(data, manager)


class Action(object):

    permissions = ()
    metrics = ()

    log = logging.getLogger("custodian.actions")

    executor_factory = ThreadPoolExecutor
    permissions = ()
    schema = {'type': 'object'}
    schema_alias = None

    def __init__(self, data=None, manager=None, log_dir=None):
        self.data = data or {}
        self.manager = manager
        self.log_dir = log_dir

    def get_permissions(self):
        return self.permissions

    def validate(self):
        return self

    @property
    def name(self):
        return self.__class__.__name__.lower()

    def process(self, resources):
        raise NotImplementedError(
            "Base action class does not implement behavior")

    def _run_api(self, cmd, *args, **kw):
        try:
            return cmd(*args, **kw)
        except ClientError as e:
            if (e.response['Error']['Code'] == 'DryRunOperation' and
            e.response['ResponseMetadata']['HTTPStatusCode'] == 412 and
            'would have succeeded' in e.response['Error']['Message']):
                return self.log.info(
                    "Dry run operation %s succeeded" % (
                        self.__class__.__name__.lower()))
            raise


BaseAction = Action


class EventAction(BaseAction):
    """Actions which receive lambda event if present
    """
