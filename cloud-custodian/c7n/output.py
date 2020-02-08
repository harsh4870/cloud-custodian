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
Outputs metrics, logs, stats, traces, and structured records across
a variety of sinks.

See docs/usage/outputs.rst

"""
from __future__ import absolute_import, division, print_function, unicode_literals

import contextlib
from datetime import datetime
import json
import gzip
import logging
import os
import shutil
import time
import uuid


from c7n.exceptions import InvalidOutputConfig
from c7n.registry import PluginRegistry
from c7n.utils import parse_url_config

try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False

log = logging.getLogger('custodian.output')


# TODO remove
DEFAULT_NAMESPACE = "CloudMaid"


class OutputRegistry(PluginRegistry):

    default_protocol = None

    def select(self, selector, ctx):
        if not selector:
            return self['default'](ctx, {'url': selector})
        if self.default_protocol and '://' not in selector:
            selector = "{}://{}".format(
                self.default_protocol, selector)
        for k in self.keys():
            if selector.startswith(k):
                return self[k](ctx, parse_url_config(selector))
        raise InvalidOutputConfig("Invalid %s: %s" % (
            self.plugin_type,
            selector))


class BlobOutputRegistry(OutputRegistry):

    default_protocol = "file"


class LogOutputRegistry(OutputRegistry):

    default_protocol = "aws"


class MetricsRegistry(OutputRegistry):

    def select(self, selector, ctx):
        # Compatibility for boolean configuration
        if isinstance(selector, bool) and selector:
            selector = 'aws'
        return super(MetricsRegistry, self).select(selector, ctx)


api_stats_outputs = OutputRegistry('c7n.output.api_stats')
blob_outputs = BlobOutputRegistry('c7n.output.blob')
log_outputs = LogOutputRegistry('c7n.output.logs')
metrics_outputs = MetricsRegistry('c7n.output.metrics')
tracer_outputs = OutputRegistry('c7n.output.tracer')
sys_stats_outputs = OutputRegistry('c7n.output.sys_stats')


@tracer_outputs.register('default')
class NullTracer(object):
    """Tracing provides for detailed analytics of a policy execution.

    Uses native cloud provider integration (xray, stack driver trace).
    """
    def __init__(self, ctx, config=None):
        self.ctx = ctx
        self.config = config or {}

    @contextlib.contextmanager
    def subsegment(self, name):
        """Create a named subsegment as a context manager
        """
        yield self

    def __enter__(self):
        """Enter main segment for policy execution.
        """

    def __exit__(self, exc_type=None, exc_value=None, exc_traceback=None):
        """Exit main segment for policy execution.
        """


class DeltaStats(object):
    """Capture stats (dictionary of string->integer) as a stack.

    Popping the stack automatically creates a delta of the last
    stack element to the current stats.
    """
    def __init__(self, ctx, config=None):
        self.ctx = ctx
        self.config = config or {}
        self.snapshot_stack = []

    def push_snapshot(self):
        self.snapshot_stack.append(self.get_snapshot())

    def pop_snapshot(self):
        return self.delta(
            self.snapshot_stack.pop(), self.get_snapshot())

    def get_snapshot(self):
        return {}

    def delta(self, before, after):
        delta = {}
        for k in before:
            val = after[k] - before[k]
            if val:
                delta[k] = val
        return delta


@sys_stats_outputs.register('default')
@api_stats_outputs.register('default')
class NullStats(object):
    """Execution statistics/metrics collection.

    Encompasses concrete implementations over system stats (memory, cpu, cache size)
    and api calls.

    The api supports stack nested snapshots, with delta consumption to support
    tracing metadata annotation across nested subsegments.
    """

    def __init__(self, ctx, config=None):
        self.ctx = ctx
        self.config = config or {}

    def push_snapshot(self):
        """Take a snapshot of the system stats and append to the stack."""

    def pop_snapshot(self):
        """Remove a snapshot from the snack and return a delta of the current stats to it.
        """
        return {}

    def get_metadata(self):
        """Return default of current to last snapshot, without popping.
        """
        return {}

    def __enter__(self):
        """Push a snapshot
        """

    def __exit__(self, exc_type=None, exc_value=None, exc_traceback=None):
        """Pop a snapshot
        """


@sys_stats_outputs.register('psutil', condition=HAVE_PSUTIL)
class SystemStats(DeltaStats):
    """Collect process statistics via psutil as deltas over policy execution.
    """
    def __init__(self, ctx, config=None):
        super(SystemStats, self).__init__(ctx, config)
        self.process = psutil.Process(os.getpid())

    def __enter__(self):
        self.push_snapshot()

    def __exit__(self):
        self.pop_snapshot()

    def get_metadata(self):
        if self.snapshot_stack:
            return self.delta(self.snapshot_stack[-1], self.get_snapshot())
        return self.get_snapshot()

    def get_snapshot(self):
        snapshot = {
            'num_threads': self.process.num_threads(),
            'snapshot_time': time.time(),
            'cache_size': self.ctx.policy.get_cache().size()
        }

        # no num_fds on Windows, but likely num_handles
        if hasattr(self.process, "num_fds"):
            snapshot['num_fds'] = self.process.num_fds()
        elif hasattr(self.process, "num_handles"):
            snapshot['num_handles'] = self.process.num_handles()

        with self.process.oneshot():
            # simpler would be json.dumps(self.process.as_dict()), but
            # that complicates delta diffing between snapshots.
            cpu_time = self.process.cpu_times()
            snapshot['cpu_user'] = cpu_time.user
            snapshot['cpu_system'] = cpu_time.system
            (snapshot['num_ctx_switches_voluntary'],
                snapshot['num_ctx_switches_involuntary']) = self.process.num_ctx_switches()
            # io counters ( not available on osx)
            if getattr(self.process, 'io_counters', None):
                try:
                    io = self.process.io_counters()
                    for counter in (
                            'read_count', 'write_count',
                            'write_bytes', 'read_bytes'):
                        snapshot[counter] = getattr(io, counter)
                except NotImplementedError:
                    # some old kernels and Windows Linux Subsystem throw this
                    pass
            # memory counters
            mem = self.process.memory_info()
            for counter in (
                    'rss', 'vms', 'shared', 'text', 'data', 'lib',
                    'pfaults', 'pageins'):
                v = getattr(mem, counter, None)
                if v is not None:
                    snapshot[counter] = v
        return snapshot


class Metrics(object):

    permissions = ()
    namespace = DEFAULT_NAMESPACE
    BUFFER_SIZE = 20

    def __init__(self, ctx, config=None):
        self.ctx = ctx
        self.config = config
        self.buf = []

    def _format_metric(self, key, value, unit, dimensions):
        raise NotImplementedError("subclass responsiblity")

    def _put_metrics(self, ns, metrics):
        raise NotImplementedError("subclass responsiblity")

    def flush(self):
        if self.buf:
            self._put_metrics(self.namespace, self.buf)
            self.buf = []

    def put_metric(self, key, value, unit, buffer=True, **dimensions):
        point = self._format_metric(key, value, unit, dimensions)
        self.buf.append(point)
        if buffer:
            # Max metrics in a single request
            if len(self.buf) >= self.BUFFER_SIZE:
                self.flush()
        else:
            self.flush()

    def get_metadata(self):
        return list(self.buf)


@metrics_outputs.register('default')
class LogMetrics(Metrics):
    """Default metrics collection.

    logs metrics, default handler should send to stderr
    """
    def _put_metrics(self, ns, metrics):
        for m in metrics:
            if m['MetricName'] not in ('ActionTime', 'ResourceTime'):
                log.debug(self.render_metric(m))

    def render_metric(self, m):
        label = "metric:%s %s:%s" % (m['MetricName'], m['Unit'], m['Value'])
        for d in m['Dimensions']:
            label += " %s:%s" % (d['Name'].lower(), d['Value'].lower())
        return label

    def _format_metric(self, key, value, unit, dimensions):
        d = {
            "MetricName": key,
            "Timestamp": datetime.now(),
            "Value": value,
            "Unit": unit}
        d["Dimensions"] = [
            {"Name": "Policy", "Value": self.ctx.policy.name},
            {"Name": "ResType", "Value": self.ctx.policy.resource_type}]
        for k, v in dimensions.items():
            d['Dimensions'].append({"Name": k, "Value": v})
        return d

    def get_metadata(self):
        res = []
        for k in self.buf:
            k = dict(k)
            k.pop('Dimensions', None)
            res.append(k)
        return res


class LogOutput(object):

    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    def __init__(self, ctx, config=None):
        self.ctx = ctx
        self.config = config or {}
        self.handler = None

    def get_handler(self):
        raise NotImplementedError()

    def __enter__(self):
        log.debug("Storing output with %s" % repr(self))
        self.join_log()
        return self

    def __exit__(self, exc_type=None, exc_value=None, exc_traceback=None):
        self.leave_log()
        if exc_type is not None:
            log.exception("Error while executing policy")

    def join_log(self):
        self.handler = self.get_handler()
        self.handler.setLevel(logging.DEBUG)
        self.handler.setFormatter(logging.Formatter(self.log_format))
        mlog = logging.getLogger('custodian')
        mlog.addHandler(self.handler)

    def leave_log(self):
        mlog = logging.getLogger('custodian')
        mlog.removeHandler(self.handler)
        self.handler.flush()
        self.handler.close()


@log_outputs.register('default')
class LogFile(LogOutput):

    def __repr__(self):
        return "<LogFile file://%s>" % self.log_path

    @property
    def log_path(self):
        return os.path.join(
            self.ctx.log_dir, 'custodian-run.log')

    def get_handler(self):
        return logging.FileHandler(self.log_path)


@blob_outputs.register('file')
@blob_outputs.register('default')
class DirectoryOutput(object):

    permissions = ()

    def __init__(self, ctx, config):
        self.ctx = ctx
        self.config = config

        output_path = self.get_output_path(config['url'])
        if output_path.startswith('file://'):
            output_path = output_path[len('file://'):]

        self.root_dir = output_path
        if self.root_dir and not os.path.exists(self.root_dir):
            os.makedirs(self.root_dir)

    def __enter__(self):
        return

    def __exit__(self, exc_type=None, exc_value=None, exc_traceback=None):
        return

    def __repr__(self):
        return "<%s to dir:%s>" % (self.__class__.__name__, self.root_dir)

    def compress(self):
        # Compress files individually so thats easy to walk them, without
        # downloading tar and extracting.
        for root, dirs, files in os.walk(self.root_dir):
            for f in files:
                fp = os.path.join(root, f)
                with gzip.open(fp + ".gz", "wb", compresslevel=7) as zfh:
                    with open(fp, "rb") as sfh:
                        shutil.copyfileobj(sfh, zfh, length=2**15)
                    os.remove(fp)

    def get_output_path(self, output_url):
        if '{' not in output_url:
            return os.path.join(output_url, self.ctx.policy.name)
        return output_url.format(**self.get_output_vars())

    def get_output_vars(self):
        data = {
            'account_id': self.ctx.options.account_id,
            'region': self.ctx.options.region,
            'policy_name': self.ctx.policy.name,
            'now': datetime.utcnow(),
            'uuid': str(uuid.uuid4())}
        return data

    def get_resource_set(self):
        record_path = os.path.join(self.root_dir, 'resources.json')

        if not os.path.exists(record_path):
            return []

        mdate = datetime.fromtimestamp(
            os.stat(record_path).st_ctime)

        with open(record_path) as fh:
            records = json.load(fh)
            [r.__setitem__('CustodianDate', mdate) for r in records]
            return records
