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

# From drgn:
# EASY-INSTALL-ENTRY-SCRIPT: 'drgn==0.0.24','console_scripts','drgn'
import os
import re
import sys

import drgn.cli

home = os.getenv('GHIDRA_HOME')

if os.path.isdir(f'{home}/ghidra/.git'):
    sys.path.append(
        f'{home}/ghidra/Ghidra/Debug/Debugger-agent-drgn/build/pypkg/src')
    sys.path.append(
        f'{home}/ghidra/Ghidra/Debug/Debugger-rmi-trace/build/pypkg/src')
elif os.path.isdir(f'{home}/.git'):
    sys.path.append(
        f'{home}/Ghidra/Debug/Debugger-agent-drgn/build/pypkg/src')
    sys.path.append(
        f'{home}/Ghidra/Debug/Debugger-rmi-trace/build/pypkg/src')
else:
    sys.path.append(
        f'{home}/Ghidra/Debug/Debugger-agent-drgn/pypkg/src')
    sys.path.append(f'{home}/Ghidra/Debug/Debugger-rmi-trace/pypkg/src')


def main():
    from ghidradrgn import commands as cmd
    cmd.ghidra_trace_connect(address=os.getenv('GHIDRA_TRACE_RMI_ADDR'))
    cmd.ghidra_trace_create(start_trace=True)
    cmd.ghidra_trace_txstart()
    cmd.ghidra_trace_put_all()
    cmd.ghidra_trace_txcommit()
    cmd.ghidra_trace_activate()
    drgn.cli.run_interactive(cmd.prog)
    

if __name__ == '__main__':
    main()
    
    
