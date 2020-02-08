# Copyright 2018-2019 Capital One Services, LLC
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
import atexit
from functools import partial
import json
import os
from six.moves.urllib.parse import urlparse

import tempfile
import vcr

from c7n.testing import TestUtils
from c7n.resources import load_resources

from c7n_kube.client import Session


load_resources()

RECORDED_HOST = 'ghost'

KUBE_CONFIG = {
    'apiVersion': 1,
    'kind': 'Config',
    'current-context': 'c7n-test',
    'contexts': [{
        'name': 'c7n-test',
        'context': {
            'cluster': 'c7n-ghost', 'user': 'c7n-test-user'}}],
    'clusters': [
        {'name': 'c7n-ghost',
         'cluster': {
             'server': 'https://ghost'}},
    ],
    'users': [
        {'name': 'c7n-test-user',
         'user': {'config': {}}}
    ],
}


def init_kube_config():
    fh = tempfile.NamedTemporaryFile(delete=False)
    fh.write(json.dumps(KUBE_CONFIG, indent=2).encode('utf8'))
    fh.flush()
    atexit.register(os.unlink, fh.name)
    return fh.name


class KubeTest(TestUtils):

    KubeConfigPath = init_kube_config()
    recording = False

    def replay_flight_data(self, name=None):
        kw = self._get_vcr_kwargs()
        kw['record_mode'] = 'none'
        self.myvcr = self._get_vcr(**kw)
        cm = self.myvcr.use_cassette(
            name or self._get_cassette_name())
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        return partial(Session, config_file=self.KubeConfigPath)

    def record_flight_data(self, name=None):
        kw = self._get_vcr_kwargs()
        kw['record_mode'] = 'all'
        kw['before_record_request'] = self._record_change_host
        self.myvcr = self._get_vcr(**kw)

        flight_path = os.path.join(
            kw['cassette_library_dir'], name or self._get_cassette_name())
        if os.path.exists(flight_path):
            os.unlink(flight_path)

        cm = self.myvcr.use_cassette(name or self._get_cassette_name())
        self.recording = True
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)

        return Session

    def _get_vcr_kwargs(self):
        return dict(filter_headers=['authorization'],
                    cassette_library_dir=self._get_cassette_library_dir())

    def _get_vcr(self, **kwargs):
        myvcr = vcr.VCR(**kwargs)
        myvcr.register_matcher('kubematcher', self._kube_matcher)
        myvcr.match_on = ['kubematcher', 'method']
        return myvcr

    def _get_cassette_library_dir(self):
        return os.path.join(
            os.path.dirname(__file__),
            'data', 'flights')

    def _get_cassette_name(self):
        return '{0}.{1}.yaml'.format(self.__class__.__name__,
                                     self._testMethodName)

    def _kube_matcher(self, *args):
        return True

    def _record_change_host(self, request):
        parsed = urlparse(request.uri)
        request.uri = parsed.__class__(
            parsed.scheme,
            RECORDED_HOST,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment).geturl()
        return request
