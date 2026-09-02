# Override the "info proc mappings" command in GDB to fetch them from a winedbg target
#
# To use:
#  1. Use winedbg on Linux to launch gdbserver.exe with your target binary:
#        winedbg --gdb --no-start --port 54321 target.exe
#  2. Connect Ghidra to winedbg on Linux using gdb-remote
#  3. From the interpreter, run:
#
#        source winedbg-proc-mappings.py
#        source winedbg_info_proc_mappings.gdb
#
#     Note that you may need to provide full paths to the scripts

define info proc mappings
  python
gdb.execute("winedbg-proc-mappings")
  end
end
