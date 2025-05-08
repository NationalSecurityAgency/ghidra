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
This file holds utilities required by Python-based connectors. At the
moment, that includes all connectors except the ones targeting Java
applications. While uncommon, it is possible that dependencies turn up
missing on a remote target, and so the gmodutils.py file will not be
present. However, by the time such dependencies turn up missing,
whether remote or local, the PYTHONPATH should already include this
module, and so we place the setup logic here.
"""
import os
from typing import List, Sequence


home = os.getenv('GHIDRA_HOME')


def ghidra_module_src(name: str) -> str:
    installed = f'{home}/Ghidra/{name}/pypkg'
    if os.path.isdir(installed):
        return installed
    dev1 = f'{home}/Ghidra/{name}/src/main/py'
    if os.path.isdir(dev1):
        return dev1
    dev2 = f'{home}/ghidra/Ghidra/{name}/src/main/py'
    if os.path.isdir(dev2):
        return dev2
    raise Exception(f"""
Cannot find Python source for {name}.
If this is a remote system, we shouldn't even be here. Chances are,
the Python dependencies required by ghidra on the remote system were
removed or replaced with incompatible versions. If this is a local
system, your installation or development repo may be corrupt.
""")


def get_module_dependencies(name: str) -> List[str]:
    src = ghidra_module_src(name)
    # Can't rely on tomllib until Python 3.11 is minimum requirement.
    # And, I'm in a place where I presume deps are missing, so do this garbage
    # of a parse job.
    with open(f"{src}/pyproject.toml") as project:
        seen_deps = False
        result: List[str] = []
        for l in project.readlines():
            l = l.strip()
            if l == "dependencies = [":
                seen_deps = True
            elif seen_deps and l == ']':
                return [r for r in result if not 'ghidra' in r]
            elif seen_deps:
                if l.endswith(','): # Last one may not have ,
                    l = l[:-1].strip()
                result.append(l[1:-1]) # Remove 's or "s
        raise Exception("Could not parse pyproject.toml")


def prompt_mitigation(msg: str, prompt: str) -> bool:
    print("""
--------------------------------------------------------------------------------
!!!                       INCORRECT OR INCOMPLETE SETUP                      !!!
--------------------------------------------------------------------------------
""")
    print(msg)
    print("")
    print("Select KEEP if you're seeing this in an error dialog.")
    print(f"{prompt} [Y/n] ", end="")
    answer = input()
    return answer == 'y' or answer == 'Y' or answer == ''


def mitigate_by_pip_install(*args: str) -> None:
    import sys
    import runpy
    sys.argv = [
        'pip', 'install', '--force-reinstall', *args
    ]
    os.environ['PIP_BREAK_SYSTEM_PACKAGES'] = '1'
    runpy.run_module("pip", run_name="__main__")


def prompt_and_mitigate_dependencies(name: str) -> None:
    deps = get_module_dependencies(name)
    deps_str = ' '.join(f"'{d}'" for d in deps)
    answer = prompt_mitigation("""
It appears dependencies are missing or have the wrong version. This can happen
if you forgot to install the required packages. This can also happen if you
installed the packages to a different Python environment than is being used
right now.

This script is about to offer automatic resolution. If you'd like to resolve
this manually, answer no to the next question and then see Ghidra's help by
pressing F1 in the dialog of launch parameters.

WARNING: Answering yes to the next question will invoke pip to try to install
missing or incorrectly-versioned dependencies. It may attempt to find packages
from your configured PyPI mirror. If you have not configured one, it will
connect to the official one.

WARNING: We invoke pip with the --break-system-packages flag, because some
debuggers that embed Python (gdb, lldb) may not support virtual environments,
and so the packages must be installed to your user environment.

NOTE: Automatic resolution may cause this session to terminate. When it has
finished, close this terminal, and try launching again.
""", f"Would you like to install {deps_str}?")

    if answer:
        mitigate_by_pip_install('-f', '../../pypkg/dist', *deps)

