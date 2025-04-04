#@title remote gdb
#@image-opt arg:1
#@desc <html><body width="300px">
#@desc   <h3>Launch with local <tt>gdb</tt> and connect to a stub (e.g., <tt>gdbserver</tt>)</h3>
#@desc   <p>
#@desc     This will start <tt>gdb</tt> on the local system and then use it to connect to the remote system. 
#@desc     For setup instructions, press <b>F1</b>. 
#@desc   </p>
#@desc </body></html>
#@menu-group remote
#@icon icon.debugger
#@help gdb#remote
#@enum TargetType:str remote extended-remote
#@enum Endian:str auto big little
#@arg :file "Image" "The target binary executable image (a copy on the local system)"
#@env OPT_TARGET_TYPE:TargetType="remote" "Target" "The type of remote target"
#@env OPT_HOST:str="localhost" "Host" "The hostname of the target"
#@env OPT_PORT:int=9999 "Port" "The host's listening port"
#@env OPT_GDB_PATH:file="gdb" "gdb command" "The path to gdb on the local system. Omit the full path to resolve using the system PATH."
#@env OPT_ARCH:str="auto" "Architecture" "Target architecture override"
#@env OPT_ENDIAN:Endian="auto" "Endian" "Target byte order"

[IO.DirectoryInfo] $repo = "$Env:GHIDRA_HOME\.git"
[IO.DirectoryInfo] $repoParent = "$Env:GHIDRA_HOME\ghidra\.git"
if ($repo.Exists) {
	$pypathGdb =   "$Env:GHIDRA_HOME\Ghidra\Debug\Debugger-agent-gdb\build\pypkg\src"
	$pypathTrace = "$Env:GHIDRA_HOME\Ghidra\Debug\Debugger-rmi-trace\build\pypkg\src"
}
elseif ($repoParent.Exists) {
	$pypathGdb =   "$Env:GHIDRA_HOME\ghidra\Ghidra\Debug\Debugger-agent-gdb\build\pypkg\src"
	$pypathTrace = "$Env:GHIDRA_HOME\ghidra\Ghidra\Debug\Debugger-rmi-trace\build\pypkg\src"
}
else {
	$pypathGdb =   "$Env:GHIDRA_HOME\Ghidra\Debug\Debugger-agent-gdb\pypkg\src"
	$pypathTrace = "$Env:GHIDRA_HOME\Ghidra\Debug\Debugger-rmi-trace\pypkg\src"
}
$Env:PYTHONPATH = "$pypathGdb;$pypathTrace;$Env:PYTHONPATH"

$arglist = @()

$arglist+=("-q")
$arglist+=("-ex", "`"set pagination off`"")
$arglist+=("-ex", "`"set confirm off`"")
$arglist+=("-ex", "`"show version`"")
$arglist+=("-ex", "`"python import ghidragdb`"")
$arglist+=("-ex", "`"set architecture $Env:OPT_ARCH`"")
$arglist+=("-ex", "`"set endian $Env:OPT_ENDIAN`"")
if ("$($args[0])" -ne "") {
	$image = $args[0] -replace "\\", "\\\\"
	$arglist+=("-ex", "`"file '$image'`"")
}
$arglist+=("-ex", "`"echo Connecting to $Env:OPT_HOST`:$Env:OPT_PORT... `"")
$arglist+=("-ex", "`"target $Env:OPT_TARGET_TYPE $Env:OPT_HOST`:$Env:OPT_PORT`"")
$arglist+=("-ex", "`"ghidra trace connect '$Env:GHIDRA_TRACE_RMI_ADDR'`"")
$arglist+=("-ex", "`"ghidra trace start`"")
$arglist+=("-ex", "`"ghidra trace sync-enable`"")
$arglist+=("-ex", "`"ghidra trace sync-synth-stopped`"")
$arglist+=("-ex", "`"set confirm on`"")
$arglist+=("-ex", "`"set pagination on`"")

Start-Process -FilePath $Env:OPT_GDB_PATH -ArgumentList $arglist -NoNewWindow -Wait
