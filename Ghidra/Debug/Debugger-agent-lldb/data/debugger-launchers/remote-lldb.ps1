#@title lldb remote (gdb)
#@image-opt arg:1
#@desc <html><body width="300px">
#@desc   <h3>Launch with local <tt>lldb</tt> and connect to a stub (e.g., <tt>gdbserver</tt>)</h3>
#@desc   <p>
#@desc     This will start <tt>lldb</tt> on the local system and then use it to connect to the remote system.
#@desc     For setup instructions, press <b>F1</b>.
#@desc   </p>
#@desc </body></html>
#@menu-group lldb
#@icon icon.debugger
#@help lldb#remote
#@depends Debugger-rmi-trace
#@arg :file "Image" "The target binary executable image (a copy on the local system)"
#@env OPT_HOST:str="localhost" "Host" "The hostname of the target"
#@env OPT_PORT:str="9999" "Port" "The host's listening port"
#@env OPT_ARCH:str="" "Architecture" "Target architecture override"
#@env OPT_LLDB_PATH:file="lldb" "lldb command" "The path to lldb on the local system. Omit the full path to resolve using the system PATH."

. ..\support\lldbsetuputils.ps1

$pypathTrace = Ghidra-Module-PyPath "Debugger-rmi-trace"
$pypathLldb = Ghidra-Module-PyPath
$Env:PYTHONPATH = "$pypathLldb;$pypathTrace;$Env:PYTHONPATH"

$arglist = Compute-Lldb-Remote-Args `
    -TargetImage $args[0] `
    -TargetCx "gdb-remote $Env:OPT_HOST`:$Env:OPT_PORT" `
    -RmiAddress "$Env:GHIDRA_TRACE_RMI_ADDR"

Start-Process -FilePath $arglist[0] -ArgumentList $arglist[1..$arglist.Count] -NoNewWindow -Wait
