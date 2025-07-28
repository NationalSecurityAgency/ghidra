#@title gdb + qemu-system
#@image-opt env:OPT_TARGET_IMG
#@desc <html><body width="300px">
#@desc   <h3>Launch with <tt>qemu-system</tt> and connect with <tt>gdb</tt></h3>
#@desc   <p>
#@desc     This will launch the target on the local machine using <tt>qemu-system</tt>.
#@desc     Then in a second terminal, it will connect <tt>gdb</tt> to QEMU's GDBstub.
#@desc     For setup instructions, press <b>F1</b>.
#@desc   </p>
#@desc </body></html>
#@menu-group gdb
#@icon icon.debugger
#@help gdb#qemu
#@depends Debugger-rmi-trace
#@enum Endian:str auto big little
#@env OPT_TARGET_IMG:file!="" "Image" "The target binary executable image"
#@env GHIDRA_LANG_EXTTOOL_qemu_system:file="" "QEMU command" "The path to qemu-system for the target architecture."
#@env QEMU_GDB:int=1234 "QEMU Port" "Port for gdb connection to qemu"
#@env OPT_EXTRA_QEMU_ARGS:str="" "Extra qemu arguments" "Extra arguments to pass to qemu. Use with care."
#@env OPT_GDB_PATH:file="gdb-multiarch" "gdb command" "The path to gdb. Omit the full path to resolve using the system PATH."
#@env OPT_ARCH:str="auto" "Architecture" "Target architecture"
#@env OPT_ENDIAN:Endian="auto" "Endian" "Target byte order"
#@env OPT_EXTRA_TTY:bool=false "QEMU TTY" "Provide a separate terminal emulator for qemu."

. ..\support\gdbsetuputils.ps1

$pypathTrace = Ghidra-Module-PyPath "Debugger-rmi-trace"
$pypathGdb = Ghidra-Module-PyPath
$Env:PYTHONPATH = "$pypathGdb;$pypathTrace;$Env:PYTHONPATH"

$qemuargs = @("`"$Env:GHIDRA_LANG_EXTTOOL_qemu_system`"")
if ("$Env:OPT_EXTRA_QEMU_ARGS" -ne "") {
	$qemuargs+=("$Env:OPT_EXTRA_QEMU_ARGS")
}
$qemuargs+=("-gdb", "tcp::$Env:QEMU_GDB", "-S")
$qemuargs+=("`"$Env:OPT_TARGET_IMG`"")

if ("$Env:OPT_EXTRA_TTY" -eq "true") {
	Start-Process -FilePath $qemuargs[0] -ArgumentList $qemuargs[1..$qemuargs.Count]
}
else {
	Start-Process -FilePath $qemuargs[0] -ArgumentList $qemuargs[1..$qemuargs.Count] -NoNewWindow
}

# Give QEMU a moment to open the socket
sleep -m 100

$arglist = Compute-Gdb-Remote-Args `
	-TargetImage $args[0] `
	-TargetCx "remote localhost:$Env:QEMU_GDB" `
	-RmiAddress "$Env:GHIDRA_TRACE_RMI_ADDR"

Start-Process -FilePath $arglist[0] -ArgumentList $arglist[1..$arglist.Count] -NoNewWindow -Wait
