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

cxn = os.getenv('GHIDRA_TRACE_RMI_ADDR')
target = os.getenv('OPT_TARGET_PID')


def parse_parameters():
    argc = len(sys.argv)
    global cxn, target, args, initdir
    if argc == 1:
        return True
    if argc >= 3:
        cxn = sys.argv[1]
        target = sys.argv[2]
        return True
    print("Error: expected (cxn, target, initdir, ...)")
    return False


def append_paths():
    sys.path.append(
        f"{os.getenv('MODULE_Debugger_rmi_trace_HOME')}/data/support")
    try:
        from gmodutils import ghidra_module_pypath
        sys.path.append(ghidra_module_pypath("Debugger-rmi-trace"))
        sys.path.append(ghidra_module_pypath())
    except Exception as e:
        pass


def main():
    append_paths()
    # Delay these imports until sys.path is patched
    from ghidraxdbg import commands as cmd
    from ghidraxdbg.hooks import on_state_changed
    from ghidraxdbg.util import dbg

    # So that the user can re-enter by typing repl()
    global repl
    repl = cmd.repl

    cmd.ghidra_trace_connect(cxn)
    cmd.ghidra_trace_attach(target, start_trace=False)

    try:
        dbg.wait()
    except KeyboardInterrupt as ki:
        dbg.interrupt()

    cmd.ghidra_trace_start(target)
    cmd.ghidra_trace_sync_enable()

    cmd.ghidra_trace_txstart()
    cmd.ghidra_trace_put_all()

    cmd.repl()


if __name__ == '__main__':
    try:
        main()
    except SystemExit as x:
        if x.code != 0:
            print(f"Exited with code {x.code}")
