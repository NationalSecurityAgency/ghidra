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
"""
This file holds utilities required by Python-based launch scripts. At
the moment, that includes only the launchers on Windows, since they're
just .bat files that invoke the .py file interactively. They require
this utility to set up the PYTHONPATH before importing the actual
connector's Python code.

This file MUST remain in a predictable location relative to the
working directory or module directory of the scripts needing it, so
that minimal logic is required to get it loaded.

This file CANNOT be assumed to be available on a remote target. For
that, consider ghidratrace.setuputils.
"""
import os

home = os.getenv('GHIDRA_HOME')


def ghidra_module_pypath(name: str) -> str:
    installed = f'{home}/Ghidra/{name}/pypkg/src'
    if os.path.isdir(installed):
        return installed
    dev1 = f'{home}/Ghidra/{name}/build/pypkg/src'
    if os.path.isdir(dev1):
        return dev1
    dev2 = f'{home}/ghidra/Ghidra/{name}/build/pypkg/src'
    if os.path.isdir(dev2):
        return dev2
    raise Exception(
        f"Cannot find Python source for {name}. Try gradle assemblePyPackage?")
