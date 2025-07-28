#@title gdb + gdbserver via ssh
#@image-opt arg:1
#@desc <html><body width="300px">
#@desc   <h3>Launch with local <tt>gdb</tt> and <tt>gdbserver</tt> via <tt>ssh</tt></h3>
#@desc   <p>
#@desc     This will start <tt>gdb</tt> on the local system and then use it to connect and launch the target in <tt>gdbserver</tt> on the remote system via <tt>ssh</tt>.
#@desc     For setup instructions, press <b>F1</b>.
#@desc   </p>
#@desc </body></html>
#@menu-group gdb
#@icon icon.debugger
#@help gdb#gdbserver_ssh
#@depends Debugger-rmi-trace
#@enum Endian:str auto big little
#@arg :str! "Image" "The target binary executable image on the remote system"
#@env OPT_TARGET_ARGS:str="" "Arguments" "Command-line arguments to pass to the target"
#@env OPT_SSH_PATH:file="ssh" "ssh command" "The path to ssh on the local system. Omit the full path to resolve using the system PATH."
#@env OPT_HOST:str="localhost" "[User@]Host" "The hostname or user@host"
#@env OPT_EXTRA_SSH_ARGS:str="" "Extra ssh arguments" "Extra arguments to pass to ssh. Use with care."
#@env OPT_GDBSERVER_PATH:str="gdbserver" "gdbserver command (remote)" "The path to gdbserver on the remote system. Omit the full path to resolve using the system PATH."
#@env OPT_EXTRA_GDBSERVER_ARGS:str="" "Extra gdbserver arguments" "Extra arguments to pass to gdbserver. Use with care."
#@env OPT_GDB_PATH:file="gdb" "gdb command" "The path to gdb on the local system. Omit the full path to resolve using the system PATH."
#@env OPT_ARCH:str="auto" "Architecture" "Target architecture"
#@env OPT_ENDIAN:Endian="auto" "Endian" "Target byte order"

. ..\support\gdbsetuputils.ps1

$pypathTrace = Ghidra-Module-PyPath "Debugger-rmi-trace"
$pypathGdb = Ghidra-Module-PyPath
$Env:PYTHONPATH = "$pypathGdb;$pypathTrace;$Env:PYTHONPATH"

$arglist = Compute-Gdb-Remote-Args `
	-TargetImage $args[0] `
	-TargetCx "remote | '$Env:OPT_SSH_PATH' $Env:OPT_EXTRA_SSH_ARGS '$Env:OPT_HOST' '$Env:OPT_GDBSERVER_PATH' $Env:OPT_EXTRA_GDBSERVER_ARGS - '$($args[0])' $Env:OPT_TARGET_ARGS" `
	-RmiAddress "$Env:GHIDRA_TRACE_RMI_ADDR"

Start-Process -FilePath $arglist[0] -ArgumentList $arglist[1..$arglist.Count] -NoNewWindow -Wait
