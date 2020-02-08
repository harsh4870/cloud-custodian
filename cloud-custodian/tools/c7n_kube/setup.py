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

import os
from setuptools import setup, find_packages

# read the contents of your README file
description = ""
if os.path.exists('readme.md'):
    description = open('readme.md', 'r').read()


setup(
    name="c7n_kube",
    version='0.1.1',
    description="Cloud Custodian - Kubernetes Provider",
    long_description=description,
    long_description_content_type='text/markdown',
    classifiers=[
        "Topic :: System :: Systems Administration",
        "Topic :: System :: Distributed Computing"
    ],
    url="https://github.com/cloud-custodian/cloud-custodian",
    license="Apache-2.0",
    packages=find_packages(),
    entry_points={
        "custodian.resources": [
            'kube = c7n_kube.entry:initialize_kube']
    },
    install_requires=[
        "c7n>=0.8.45.0",
        "kubernetes>=9.0.0"
    ]
)
