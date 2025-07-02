#@title gdb remote
#@image-opt arg:1
#@desc <html><body width="300px">
#@desc   <h3>Launch with local <tt>gdb</tt> and connect to a stub (e.g., <tt>gdbserver</tt>)</h3>
#@desc   <p>
#@desc     This will start <tt>gdb</tt> on the local system and then use it to connect to the remote system. 
#@desc     For setup instructions, press <b>F1</b>. 
#@desc   </p>
#@desc </body></html>
#@menu-group gdb
#@icon icon.debugger
#@help gdb#remote
#@depends Debugger-rmi-trace
#@enum TargetType:str remote extended-remote
#@enum Endian:str auto big little
#@arg :file "Image" "The target binary executable image (a copy on the local system)"
#@env OPT_TARGET_TYPE:TargetType="remote" "Target" "The type of remote target"
#@env OPT_HOST:str="localhost" "Host" "The hostname of the target"
#@env OPT_PORT:int=9999 "Port" "The host's listening port"
#@env OPT_GDB_PATH:file="gdb" "gdb command" "The path to gdb on the local system. Omit the full path to resolve using the system PATH."
#@env OPT_ARCH:str="auto" "Architecture" "Target architecture override"
#@env OPT_ENDIAN:Endian="auto" "Endian" "Target byte order"

. ..\support\gdbsetuputils.ps1

$pypathTrace = Ghidra-Module-PyPath "Debugger-rmi-trace"
$pypathGdb = Ghidra-Module-PyPath
$Env:PYTHONPATH = "$pypathGdb;$pypathTrace;$Env:PYTHONPATH"

$arglist = Compute-Gdb-Remote-Args `
    -TargetImage $args[0] `
    -TargetCx "$Env:OPT_TARGET_TYPE $Env:OPT_HOST`:$Env:OPT_PORT" `
    -RmiAddress "$Env:GHIDRA_TRACE_RMI_ADDR"

Start-Process -FilePath $arglist[0] -ArgumentList $arglist[1..$arglist.Count] -NoNewWindow -Wait
