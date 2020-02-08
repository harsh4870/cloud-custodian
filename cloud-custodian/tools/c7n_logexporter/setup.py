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

import os
from setuptools import setup


description = ""
if os.path.exists('README.md'):
    description = open('README.md', 'r').read()

setup(
    name="c7n_logexporter",
    version='0.3.2',
    description="Cloud Custodian - Cloud Watch Log S3 exporter",
    long_description=description,
    long_description_content_type='text/markdown',
    classifiers=[
        "Topic :: System :: Systems Administration",
        "Topic :: System :: Distributed Computing"
    ],
    url="https://github.com/cloud-custodian/cloud-custodian",
    license="Apache-2.0",
    py_modules=['c7n_logexporter'],
    entry_points={
        'console_scripts': [
            'c7n-log-exporter = c7n_logexporter.exporter:cli']},
    install_requires=["c7n", "click", "jsonschema"],
)
