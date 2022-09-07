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
# A GDB command for fetching /proc/{pid}/maps from a remote gdbserver,
# formatted in the style of `info proc mappings`.
#
# usage: remote-proc-mappings PID

import contextlib
import os
import threading

@contextlib.contextmanager
def pipe_fds():
    r_fd, w_fd = os.pipe()
    r_file = os.fdopen(r_fd, mode="rb")
    w_file = os.fdopen(w_fd, mode="wb")
    try:
        yield (r_file, w_file)
    finally:
        r_file.close()
        w_file.close()

class ReadThread(threading.Thread):
    def __init__(self, reader):
        super(ReadThread, self).__init__()
        self.__r = reader
        self.bytes = None

    def run(self):
        self.bytes = bytearray(self.__r.read())

def reformat_line(raw_line):
    split = raw_line.decode("utf-8").split(None, 5)
    # split[0] range
    # split[1] mode
    # split[2] offset
    # split[3] major_minor
    # split[4] inode
    # split[5] object name
    start_addr_s, end_addr_s = split[0].split("-")
    start_addr = int(start_addr_s, 16)
    end_addr = int(end_addr_s, 16)
    if len(split) == 6:
        objfile = split[5]
    else:
        objfile = ""
    return "0x{:X} 0x{:X} 0x{:X} 0x{:X} {} {}\n".format(
        start_addr, end_addr,
        end_addr - start_addr,
        int(split[2], 16),
        split[1],
        objfile,
    )

class RemoteProcMappings(gdb.Command):
    def __init__(self):
        super(RemoteProcMappings, self).__init__("remote-proc-mappings", gdb.COMMAND_STATUS)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if len(argv) != 1:
            gdb.write("usage: remote-proc-mappings PID\n", gdb.STDERR)
            return

        remote_pid = int(argv[0])

        with pipe_fds() as (r_file, w_file):
            read_thread = ReadThread(reader = r_file)
            read_thread.start()
            maps_path = "/proc/{}/maps".format(remote_pid)
            pipe_writer_path = "/dev/fd/{}".format(w_file.fileno())
            gdb.execute("remote get {} {}".format(maps_path, pipe_writer_path))
            w_file.close()
            read_thread.join()
            raw_bytes = read_thread.bytes

        for raw_line in raw_bytes.split(b"\n"):
            if raw_line:
                gdb.write(reformat_line(raw_line))

RemoteProcMappings()
