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
# A winedbg/GDB command for fetching regions using "monitor mem",
# formatted in the style of `info proc mappings`.
#
# usage: winedbg-proc-mappings

import os

def reformat_line(raw_line):
    split = raw_line.split(None, 5)
    # split[0] start
    # split[1] len
    # split[2] commit
    # split[3] type
    # split[4] mode
    # split[5] object name
    start_addr_s = split[0]
    start_addr = int(start_addr_s, 16)
    len_s = split[1]
    length = int(len_s, 16)
    end_addr = start_addr + length
    if len(split) > 4:
        rwx = split[4].lower().replace("c", "w")
    else:
        rwx = ""
    if len(split) == 6:
        objfile = split[5]
    else:
        objfile = split[2]
        if len(split) > 3:
            objfile += "_" + split[3]
        
    return "0x{:X} 0x{:X} 0x{:X} 0x{:X} {} {}\n".format(
        start_addr, end_addr,
        length,
        0,
        rwx,
        objfile,
    )

class WinedbgProcMappings(gdb.Command):
    def __init__(self):
        super(WinedbgProcMappings, self).__init__("winedbg-proc-mappings", gdb.COMMAND_STATUS)

    def invoke(self, arg, from_tty):

        for raw_line in gdb.execute("monitor mem", to_string=True).split("\n")[1:]:
            if raw_line:
                gdb.write(reformat_line(raw_line))

WinedbgProcMappings()
