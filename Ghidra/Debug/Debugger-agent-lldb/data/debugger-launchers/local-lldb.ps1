#@title lldb
#@image-opt arg:1
#@desc <html><body width="300px">
#@desc   <h3>Launch with <tt>lldb</tt></h3>
#@desc   <p>
#@desc     This will launch the target on the local machine using <tt>lldb</tt>.
#@desc     For setup instructions, press <b>F1</b>.
#@desc   </p>
#@desc </body></html>
#@menu-group lldb
#@icon icon.debugger
#@help lldb#local
#@depends Debugger-rmi-trace
#@enum StartCmd:str "process launch" "process launch --stop-at-entry"
#@arg :file "Image" "The target binary executable image"
#@env OPT_TARGET_ARGS:str="" "Arguments" "Command-line arguments to pass to the target"
#@env OPT_LLDB_PATH:file="lldb" "lldb command" "The path to lldb. Omit the full path to resolve using the system PATH."
#@env OPT_START_CMD:StartCmd="process launch" "Run command" "The lldb command to actually run the target."

. ..\support\lldbsetuputils.ps1

$pypathTrace = Ghidra-Module-PyPath "Debugger-rmi-trace"
$pypathLldb = Ghidra-Module-PyPath
$Env:PYTHONPATH = "$pypathLldb;$pypathTrace;$Env:PYTHONPATH"

$arglist = Compute-Lldb-Usermode-Args `
	-TargetImage $args[0] `
	-RmiAddress "$Env:GHIDRA_TRACE_RMI_ADDR"

Start-Process -FilePath $arglist[0] -ArgumentList $arglist[1..$arglist.Count] `
	-NoNewWindow -Wait
