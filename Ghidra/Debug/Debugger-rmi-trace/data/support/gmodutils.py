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
from typing import Optional


def ghidra_module_pypath(name: Optional[str]=None) -> str:
    mod_home_name = 'MODULE_HOME' if name is None else f'MODULE_{name.replace("-","_")}_HOME'
    mod_home = os.getenv(mod_home_name)
    installed = f'{mod_home}/pypkg/src'
    if os.path.isdir(installed):
        return installed
    dev = f'{mod_home}/build/pypkg/src'
    if os.path.isdir(dev):
        return dev
    raise Exception(
        f"Cannot find Python source for {name}. Try gradle assemblePyPackage?")
