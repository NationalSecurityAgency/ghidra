#@title remote lldb
#@image-opt arg:1
#@desc <html><body width="300px">
#@desc   <h3>Launch with local <tt>lldb</tt> and connect to a stub (e.g., <tt>gdbserver</tt>)</h3>
#@desc   <p>
#@desc     This will start <tt>lldb</tt> on the local system and then use it to connect to the remote system.
#@desc     For setup instructions, press <b>F1</b>.
#@desc   </p>
#@desc </body></html>
#@menu-group remote
#@icon icon.debugger
#@help lldb#remote
#@arg :file "Image" "The target binary executable image (a copy on the local system)"
#@env OPT_HOST:str="localhost" "Host" "The hostname of the target"
#@env OPT_PORT:str="9999" "Port" "The host's listening port"
#@env OPT_ARCH:str="" "Architecture" "Target architecture override"
#@env OPT_LLDB_PATH:file="lldb" "lldb command" "The path to lldb on the local system. Omit the full path to resolve using the system PATH."

[IO.DirectoryInfo] $repo = "$Env:GHIDRA_HOME\.git"
[IO.DirectoryInfo] $repoParent = "$Env:GHIDRA_HOME\ghidra\.git"
if ($repo.Exists) {
	$pypathLldb =  "$Env:GHIDRA_HOME\Ghidra\Debug\Debugger-agent-lldb\build\pypkg\src"
	$pypathTrace = "$Env:GHIDRA_HOME\Ghidra\Debug\Debugger-rmi-trace\build\pypkg\src"
}
elseif ($repoParent.Exists) {
	$pypathLldb =  "$Env:GHIDRA_HOME\ghidra\Ghidra\Debug\Debugger-agent-lldb\build\pypkg\src"
	$pypathTrace = "$Env:GHIDRA_HOME\ghidra\Ghidra\Debug\Debugger-rmi-trace\build\pypkg\src"
}
else {
	$pypathLldb =  "$Env:GHIDRA_HOME\Ghidra\Debug\Debugger-agent-lldb\pypkg\src"
	$pypathTrace = "$Env:GHIDRA_HOME\Ghidra\Debug\Debugger-rmi-trace\pypkg\src"
}
$Env:PYTHONPATH = "$pypathLldb;$pypathTrace;$Env:PYTHONPATH"

$arglist = @()

$arglist+=("-o", "`"version`"")
$arglist+=("-o", "`"script import ghidralldb`"")
if ("$Env:OPT_ARCH" -ne "") {
	$arglist+=("-o", "`"settings set target.default-arch $Env:OPT_ARCH`"")
}
if ("$($args[0])" -ne "") {
	$image = $args[0]
	$arglist+=("-o", "`"file '$image'`"")
}
$arglist+=("-o", "`"gdb-remote $Env:OPT_HOST`:$Env:OPT_PORT`"")
$arglist+=("-o", "`"ghidra trace connect '$Env:GHIDRA_TRACE_RMI_ADDR'`"")
$arglist+=("-o", "`"ghidra trace start`"")
$arglist+=("-o", "`"ghidra trace sync-enable`"")
$arglist+=("-o", "`"ghidra trace sync-synth-stopped`"")

Start-Process -FilePath $Env:OPT_LLDB_PATH -ArgumentList $arglist -NoNewWindow -Wait
