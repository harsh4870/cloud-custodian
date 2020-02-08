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

import datetime
import functools
import io
import jmespath
import json
import logging
import os
import re
import shutil
import tempfile
import unittest

import pytest
import mock
import six
import yaml

from c7n import policy
from c7n.loader import PolicyLoader
from c7n.ctx import ExecutionContext
from c7n.utils import reset_session_cache
from c7n.config import Bag, Config


C7N_VALIDATE = bool(os.environ.get("C7N_VALIDATE", ""))
skip_if_not_validating = unittest.skipIf(
    not C7N_VALIDATE, reason="We are not validating schemas.")
functional = pytest.mark.functional


class CustodianTestCore(object):

    custodian_schema = None
    # thread local? tests are single threaded, multiprocess execution
    policy_loader = PolicyLoader(Config.empty())
    policy_loader.default_policy_validate = C7N_VALIDATE

    def addCleanup(self, func, *args, **kw):
        raise NotImplementedError("subclass required")

    def write_policy_file(self, policy, format="yaml"):
        """ Write a policy file to disk in the specified format.

        Input a dictionary and a format. Valid formats are `yaml` and `json`
        Returns the file path.
        """
        fh = tempfile.NamedTemporaryFile(mode="w+b", suffix="." + format, delete=False)
        if format == "json":
            fh.write(json.dumps(policy).encode("utf8"))
        else:
            fh.write(yaml.dump(policy, encoding="utf8", Dumper=yaml.SafeDumper))

        fh.flush()
        self.addCleanup(os.unlink, fh.name)
        self.addCleanup(fh.close)
        return fh.name

    def get_temp_dir(self):
        """ Return a temporary directory that will get cleaned up. """
        temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, temp_dir)
        return temp_dir

    def get_context(self, config=None, session_factory=None, policy=None):
        if config is None:
            self.context_output_dir = self.get_temp_dir()
            config = Config.empty(output_dir=self.context_output_dir)
        ctx = ExecutionContext(
            session_factory, policy or Bag({
                "name": "test-policy", "provider_name": "aws"}), config)
        return ctx

    def load_policy(
        self,
        data,
        config=None,
        session_factory=None,
        validate=C7N_VALIDATE,
        output_dir=None,
        cache=False,
    ):
        pdata = {'policies': [data]}
        if not (config and isinstance(config, Config)):
            config = self._get_policy_config(
                output_dir=output_dir, cache=cache, **(config or {}))
        collection = self.policy_loader.load_data(
            pdata, validate=validate,
            file_uri="memory://test",
            session_factory=session_factory,
            config=config)
        # policy non schema validation is also lazy initialization
        [p.validate() for p in collection]
        return list(collection)[0]

    def _get_policy_config(self, **kw):
        config = kw
        config["output_dir"] = temp_dir = self.get_temp_dir()
        if config.get('cache'):
            config["cache"] = os.path.join(temp_dir, "c7n.cache")
            config["cache_period"] = 300
        return Config.empty(**config)

    def load_policy_set(self, data, config=None):
        filename = self.write_policy_file(data, format="json")
        if config:
            e = Config.empty(**config)
        else:
            e = Config.empty()
        return policy.load(e, filename)

    def patch(self, obj, attr, new):
        old = getattr(obj, attr, None)
        setattr(obj, attr, new)
        self.addCleanup(setattr, obj, attr, old)

    def change_cwd(self, work_dir=None):
        if work_dir is None:
            work_dir = self.get_temp_dir()

        cur_dir = os.path.abspath(os.getcwd())

        def restore():
            os.chdir(cur_dir)

        self.addCleanup(restore)

        os.chdir(work_dir)
        return work_dir

    def change_environment(self, **kwargs):
        """Change the environment to the given set of variables.

        To clear an environment variable set it to None.
        Existing environment restored after test.
        """
        # preserve key elements needed for testing
        for env in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION"]:
            if env not in kwargs:
                kwargs[env] = os.environ.get(env, "")

        original_environ = dict(os.environ)

        @self.addCleanup
        def cleanup_env():
            os.environ.clear()
            os.environ.update(original_environ)

        os.environ.clear()

        for key, value in list(kwargs.items()):
            if value is None:
                del (kwargs[key])
        os.environ.update(kwargs)

    def capture_logging(
        self, name=None, level=logging.INFO, formatter=None, log_file=None
    ):
        if log_file is None:
            log_file = TextTestIO()
        log_handler = logging.StreamHandler(log_file)
        if formatter:
            log_handler.setFormatter(formatter)
        logger = logging.getLogger(name)
        logger.addHandler(log_handler)
        old_logger_level = logger.level
        logger.setLevel(level)

        @self.addCleanup
        def reset_logging():
            logger.removeHandler(log_handler)
            logger.setLevel(old_logger_level)

        return log_file

    # Backport from stdlib for 2.7 compat, drop when 2.7 support is dropped.
    def assertRegex(self, text, expected_regex, msg=None):
        """Fail the test unless the text matches the regular expression."""
        if isinstance(expected_regex, six.string_types):
            assert expected_regex, "expected_regex must not be empty."
            expected_regex = re.compile(expected_regex)
        if not expected_regex.search(text):
            standardMsg = "Regex didn't match: %r not found in %r" % (
                expected_regex.pattern, text)
            # _formatMessage ensures the longMessage option is respected
            msg = self._formatMessage(msg, standardMsg)
            raise self.failureException(msg)

    def assertJmes(self, expr, instance, expected):
        value = jmespath.search(expr, instance)
        self.assertEqual(value, expected)


class _TestUtils(unittest.TestCase):
    # used to expose unittest feature set as a pytest fixture
    def test_utils(self):
        """dummy method for py2.7 unittest"""


class PyTestUtils(CustodianTestCore):
    """Pytest compatibile testing utils intended for use as fixture."""
    def __init__(self, request):
        self.request = request

        # Copy over asserts from unit test
        t = _TestUtils('test_utils')
        for n in dir(t):
            if n.startswith('assert'):
                setattr(self, n, getattr(t, n))

    def addCleanup(self, func, *args, **kw):
        self.request.addfinalizer(functools.partial(func, *args, **kw))


class TestUtils(unittest.TestCase, CustodianTestCore):

    def tearDown(self):
        self.cleanUp()

    def cleanUp(self):
        # Clear out thread local session cache
        reset_session_cache()


class TextTestIO(io.StringIO):

    def write(self, b):

        # print handles both str/bytes and unicode/str, but io.{String,Bytes}IO
        # requires us to choose. We don't have control over all of the places
        # we want to print from (think: traceback.print_exc) so we can't
        # standardize the arg type up at the call sites. Hack it here.

        if not isinstance(b, six.text_type):
            b = b.decode("utf8")
        return super(TextTestIO, self).write(b)


# Per http://blog.xelnor.net/python-mocking-datetime/
# naive implementation has issues with pypy

real_datetime_class = datetime.datetime


def mock_datetime_now(tgt, dt):

    class DatetimeSubclassMeta(type):

        @classmethod
        def __instancecheck__(mcs, obj):
            return isinstance(obj, real_datetime_class)

    class BaseMockedDatetime(real_datetime_class):
        target = tgt

        @classmethod
        def now(cls, tz=None):
            return cls.target.replace(tzinfo=tz)

        @classmethod
        def utcnow(cls):
            return cls.target

        # Python2 & Python3 compatible metaclass

    MockedDatetime = DatetimeSubclassMeta(
        b"datetime" if str is bytes else "datetime",  # hack Python2/3 port
        (BaseMockedDatetime,),
        {},
    )
    return mock.patch.object(dt, "datetime", MockedDatetime)
