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


home = os.getenv('GHIDRA_HOME')

if os.path.isdir(f'{home}\\ghidra\\.git'):
    sys.path.append(
        f'{home}\\ghidra\\Ghidra\\Debug\\Debugger-agent-dbgeng\\build\\pypkg\\src')
    sys.path.append(
        f'{home}\\ghidra\\Ghidra\\Debug\\Debugger-rmi-trace\\build\\pypkg\\src')
elif os.path.isdir(f'{home}\\.git'):
    sys.path.append(
        f'{home}\\Ghidra\\Debug\\Debugger-agent-dbgeng\\build\\pypkg\\src')
    sys.path.append(
        f'{home}\\Ghidra\\Debug\\Debugger-rmi-trace\\build\\pypkg\\src')
else:
    sys.path.append(
        f'{home}\\Ghidra\\Debug\\Debugger-agent-dbgeng\\pypkg\\src')
    sys.path.append(f'{home}\\Ghidra\\Debug\\Debugger-rmi-trace\\pypkg\\src')


def main():
    # Delay these imports until sys.path is patched
    from ghidradbg import commands as cmd
    from pybag.dbgeng import core as DbgEng
    from ghidradbg.hooks import on_state_changed
    from ghidradbg.util import dbg

    # So that the user can re-enter by typing repl()
    global repl
    repl = cmd.repl

    cmd.ghidra_trace_connect(os.getenv('GHIDRA_TRACE_RMI_ADDR'))
    target = os.getenv('OPT_TARGET_TRACE')
    if target is None or target == "":
        print("dbgeng requires a target trace - please try again.")
        cmd.ghidra_trace_disconnect()
        return
    
    cmd.ghidra_trace_open(target, start_trace=False)
    
    # TODO: HACK
    try:
        dbg.wait()
    except KeyboardInterrupt as ki:
        dbg.interrupt()

    cmd.ghidra_trace_start(target)
    cmd.ghidra_trace_sync_enable()
    
    on_state_changed(DbgEng.DEBUG_CES_EXECUTION_STATUS, DbgEng.DEBUG_STATUS_BREAK)
    cmd.repl()


if __name__ == '__main__':
    main()
