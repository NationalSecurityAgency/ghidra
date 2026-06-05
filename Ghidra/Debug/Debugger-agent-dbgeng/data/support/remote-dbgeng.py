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

import os
import sys


def append_paths():
    sys.path.append(
        f"{os.getenv('MODULE_Debugger_rmi_trace_HOME')}/data/support")
    from gmodutils import ghidra_module_pypath
    sys.path.append(ghidra_module_pypath("Debugger-rmi-trace"))
    sys.path.append(ghidra_module_pypath())


def main():
    append_paths()
    # Delay these imports until sys.path is patched
    from ghidradbg import commands as cmd
    from pybag.dbgeng import core as DbgEng
    from ghidradbg.hooks import on_state_changed
    from ghidradbg.util import dbg

    # So that the user can re-enter by typing repl()
    global repl
    repl = cmd.repl

    cmd.ghidra_trace_connect(os.getenv('GHIDRA_TRACE_RMI_ADDR'))

    os.environ['OPT_USE_DBGMODEL'] = "false"
    cmd.ghidra_trace_start("Remote")
    cmd.ghidra_trace_sync_enable()
    dbg.interrupt()

    on_state_changed(DbgEng.DEBUG_CES_EXECUTION_STATUS,
                     DbgEng.DEBUG_STATUS_BREAK)
    cmd.repl()


if __name__ == '__main__':
    try:
        main()
    except SystemExit as x:
        if x.code != 0:
            print(f"Exited with code {x.code}")
