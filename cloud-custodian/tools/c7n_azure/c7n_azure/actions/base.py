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
Actions to perform on Azure resources
"""
import abc
import logging
import sys

import six
from c7n_azure import constants
from c7n_azure.utils import ThreadHelper
from msrestazure.azure_exceptions import CloudError

from c7n.actions import BaseAction, EventAction


@six.add_metaclass(abc.ABCMeta)
class AzureBaseAction(BaseAction):
    session = None
    max_workers = constants.DEFAULT_MAX_THREAD_WORKERS
    chunk_size = constants.DEFAULT_CHUNK_SIZE
    log = logging.getLogger('custodian.azure.AzureBaseAction')

    def process(self, resources, event=None):
        self.session = self.manager.get_session()
        results, exceptions = self.process_in_parallel(resources, event)

        if len(exceptions) > 0:
            self.handle_exceptions(exceptions)

        return results

    def handle_exceptions(self, exceptions):
        """raising one exception re-raises the last exception and maintains
        the stack trace"""
        raise exceptions[0]

    def process_in_parallel(self, resources, event):
        return ThreadHelper.execute_in_parallel(
            resources=resources,
            event=event,
            execution_method=self._process_resources,
            executor_factory=self.executor_factory,
            log=self.log,
            max_workers=self.max_workers,
            chunk_size=self.chunk_size
        )

    def _log_modified_resource(self, resource, message):
        template = "Action '{}' modified '{}' in resource group '{}'."
        name = resource.get('name', 'unknown')
        rg = resource.get('resourceGroup', 'unknown')

        if message:
            template += ' ' + message

        self.log.info(template.format(self.type, name, rg),
                      extra=self._get_action_log_metadata(resource))

    def _get_action_log_metadata(self, resource):
        rid = resource.get('id')
        return {'properties': {'resource_id': rid, 'action': self.type}}

    def _process_resources(self, resources, event):
        self._prepare_processing()

        for r in resources:
            try:
                message = self._process_resource(r)
                self._log_modified_resource(r, message)
            except Exception as e:
                # only executes during test runs
                if "pytest" in sys.modules:
                    raise e
                if isinstance(e, CloudError):
                    self.log.error("{0} failed for '{1}'. {2}".format(
                        self.type, r['name'], e.message),
                        extra=self._get_action_log_metadata(r))
                else:
                    self.log.exception("{0} failed for '{1}'.".format(
                        self.type, r['name']),
                        extra=self._get_action_log_metadata(r))

    def _prepare_processing(self):
        pass

    @abc.abstractmethod
    def _process_resource(self, resource):
        raise NotImplementedError(
            "Base action class does not implement this behavior")


@six.add_metaclass(abc.ABCMeta)
class AzureEventAction(EventAction, AzureBaseAction):

    def _process_resources(self, resources, event):
        self._prepare_processing()

        for r in resources:
            try:
                message = self._process_resource(r, event)
                self._log_modified_resource(r, message)
            except Exception as e:
                # only executes during test runs
                if "pytest" in sys.modules:
                    raise e
                if isinstance(e, CloudError):
                    self.log.error("{0} failed for '{1}'. {2}".format(
                        self.type, r['name'], e.message),
                        extra=self._get_action_log_metadata(r))
                else:
                    self.log.exception("{0} failed for '{1}'.".format(
                        self.type, r['name']),
                        extra=self._get_action_log_metadata(r))

    @abc.abstractmethod
    def _process_resource(self, resource, event):
        raise NotImplementedError(
            "Base action class does not implement this behavior")
