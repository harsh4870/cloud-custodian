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

from setuptools import setup

setup(
    name="c7n_traildb",
    version='0.1',
    description="Cloud Custodian - Cloud Trail Tools",
    classifiers=[
        "Topic :: System :: Systems Administration",
        "Topic :: System :: Distributed Computing"
    ],
    url="https://github.com/cloud-custodian/cloud-custodian",
    license="Apache-2.0",
    py_modules=['c7n_traildb'],
    entry_points={
        'console_scripts': [
            'c7n-traildb = c7n_traildb.traildb:main',
            'c7n-trailts = c7n_traildb.trailts:trailts',
            'c7n-trailes = c7n_traildb.trailes:trailes',
        ]},
    install_requires=["c7n", "click", "jsonschema", "influxdb"],
)
