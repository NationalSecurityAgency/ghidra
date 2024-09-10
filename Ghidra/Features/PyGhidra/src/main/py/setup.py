#!/usr/bin/python
## ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##
# -*- coding: utf-8 -*-
import sys
from setuptools import setup


if __name__ == "__main__":
    # This is necessary so that we can build the sdist using pip wheel.
    # Unfortunately we have to have this work without having setuptools
    # which pip will install in an isolated environment from the
    # dependencies directory.
    if "bdist_wheel" in sys.argv and "sdist" not in sys.argv:
        sys.argv.append("sdist")
    setup()
