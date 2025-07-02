#@title gdb
#@image-opt arg:1
#@desc <html><body width="300px">
#@desc   <h3>Launch with <tt>gdb</tt></h3>
#@desc   <p>
#@desc     This will launch the target on the local machine using <tt>gdb</tt>.
#@desc     For setup instructions, press <b>F1</b>.
#@desc   </p>
#@desc </body></html>
#@menu-group gdb
#@icon icon.debugger
#@help gdb#local
#@depends Debugger-rmi-trace
#@enum StartCmd:str run start starti
#@enum Endian:str auto big little
#@arg :file "Image" "The target binary executable image"
#@env OPT_TARGET_ARGS:str="" "Arguments" "Command-line arguments to pass to the target"
#@env OPT_GDB_PATH:file="gdb" "gdb command" "The path to gdb. Omit the full path to resolve using the system PATH."
#@env OPT_START_CMD:StartCmd="starti" "Run command" "The gdb command to actually run the target."
#@env OPT_ARCH:str="auto" "Architecture" "Target architecture"
#@env OPT_ENDIAN:Endian="auto" "Endian" "Target byte order"

. ..\support\gdbsetuputils.ps1

$pypathTrace = Ghidra-Module-PyPath "Debugger-rmi-trace"
$pypathGdb = Ghidra-Module-PyPath
$Env:PYTHONPATH = "$pypathGdb;$pypathTrace;$Env:PYTHONPATH"

$arglist = Compute-Gdb-Usermode-Args `
	-TargetImage $args[0] `
	-RmiAddress "$Env:GHIDRA_TRACE_RMI_ADDR"

Start-Process -FilePath $arglist[0] -ArgumentList $arglist[1..$arglist.Count] `
	-NoNewWindow -Wait
