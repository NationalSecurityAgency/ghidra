# Override the "info proc mappings" command in GDB to report the full 64-bit address space
#
# This presents the space in two regions, low and high, to avoid signedness bugs in Ghidra.
#
# To use:
#  1. Consider the actual memory size of your target and copy and/or adjust this script
#  2. Connect Ghidra to GDB on Linux
#  3. From the interpreter, run:
#
#        source fallback_info_proc_mappings.gdb
#
#     Note that you may need to provide the full path to the script
#
# You can now launch or connect to your target in the usual way. This may cause Ghidra to display
# more memory than is actually present on the target. As a result, randomly scrolling in the
# dynamic listing may cause several erroneous reads, which may in turn may cause the target and/or
# GDB to crash. Use with caution. The more accurate your memory map, the safer.
#
# Note that the connection should only be used with the target for which this script was tailored.
# Re-using the connection for another target may result in sub-optimal performance and/or undefined
# behavior.

define info proc mappings
echo 0x0 0x7FFFFFFFFFFFFFFF 0x8000000000000000 0x0 lomem \n
echo 0x8000000000000000 0xFFFFFFFFFFFFFFFF 0x8000000000000000 0x0 himem
end
