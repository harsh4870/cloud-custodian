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

from setuptools import setup, find_packages
import os

description = ""
if os.path.exists('README.md'):
    description = open('README.md').read()

setup(
    name="c7n_salactus",
    version='0.3.0',
    description="Cloud Custodian - Salactus S3",
    long_description=description,
    classifiers=[
        "Topic :: System :: Systems Administration",
        "Topic :: System :: Distributed Computing"
    ],
    url="https://github.com/cloud-custodian/cloud-custodian",
    author="Kapil Thangavelu",
    license="Apache-2.0",
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'c7n-salactus = c7n_salactus.cli:cli']},
    install_requires=["c7n", "click", "rq", "redis"],
)
