## ###
#  IP: GHIDRA
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#       http://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
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
    from ghidrattd import commands as cmd
    from ghidrattd import hooks
    ###from ghidrattd.util import dbg

    cmd.ghidra_trace_connect(os.getenv('GHIDRA_TRACE_RMI_ADDR'))
    args = os.getenv('OPT_TARGET_ARGS')
    if args:
        args = ' ' + args
    cmd.ghidra_trace_create(
        os.getenv('OPT_TARGET_IMG') + args, start_trace=True)
    cmd.ghidra_trace_sync_enable()
    hooks.on_stop()

    cmd.repl()


if __name__ == '__main__':
    main()
