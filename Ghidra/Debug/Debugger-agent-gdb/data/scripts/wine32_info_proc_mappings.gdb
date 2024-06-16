# Override the "info proc mappings" command in GDB to fetch them from a remote wine32 target
#
# To use:
#  1. Read the documentation for getpid-linux-i386.gdb carefully! You may need to copy and/or make
#     target-specific adjustments, since it needs to inject machine code. Some preliminary static
#     analysis may be required.
#  2. Use Wine on Linux to launch gdbserver.exe with your target binary
#  3. Connect Ghidra to GDB on Linux
#  4. From the interpreter, run:
#
#        source getpid-linux-i386.gdb
#        source remote-proc-mappings.py
#        source wine32_info_proc_mappings.gdb
#
#     Note that you may need to provide full paths to the scripts
#
# You can now connect to the "remote" gdbserver.exe in the usual way, and Ghidra's Debugger should
# work as usual. Note that the connection should only be used for 32-bit x86 Windows targets
# running under Wine for Linux. Re-using the connection for another target may result in undefined
# behavior.

define info proc mappings
  python
remote_pid = gdb.execute("getpid-linux-i386", to_string=True).strip()
gdb.execute("remote-proc-mappings {}".format(remote_pid))
  end
end
