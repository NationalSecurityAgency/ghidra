::@timeout 60000
::@title gdb via ssh
::@image-opt env:OPT_TARGET_IMG
::@desc <html><body width="300px">
::@desc   <h3>Launch with <tt>gdb</tt> via <tt>ssh</tt></h3>
::@desc   <p>
::@desc     This will launch the target on a remote machine using <tt>gdb</tt> via <tt>ssh</tt>.
::@desc     For setup instructions, press <b>F1</b>.
::@desc   </p>
::@desc </body></html>
::@menu-group remote
::@icon icon.debugger
::@help TraceRmiLauncherServicePlugin#gdb_ssh
::@enum StartCmd:str run start starti
::@env OPT_TARGET_IMG:str="" "Image" "The target binary executable image on the remote system"
::@env OPT_TARGET_ARGS:str="" "Arguments" "Command-line arguments to pass to the target"
::@env OPT_SSH_PATH:file="ssh" "ssh command" "The path to ssh on the local system. Omit the full path to resolve using the system PATH."
::@env OPT_HOST:str="localhost" "[User@]Host" "The hostname or user@host"
::@env OPT_REMOTE_PORT:int=12345 "Remote Trace RMI Port" "A free port on the remote end to receive and forward the Trace RMI connection."
::@env OPT_EXTRA_SSH_ARGS:str="" "Extra ssh arguments" "Extra arguments to pass to ssh. Use with care."
::@env OPT_GDB_PATH:str="gdb" "gdb command" "The path to gdb on the remote system. Omit the full path to resolve using the system PATH."
::@env OPT_START_CMD:StartCmd="starti" "Run command" "The gdb command to actually run the target."
::@env OPT_ARCH:str="i386:x86-64" "Architecture" "Target architecture"

@echo off

IF "%OPT_TARGET_IMG%" == "" (
  set cmd=TERM='%TERM%' '%OPT_GDB_PATH%' ^
    -q ^
    -ex 'set pagination off' ^
    -ex 'set confirm off' ^
    -ex 'show version' ^
    -ex 'python import ghidragdb' ^
    -ex 'set architecture %OPT_ARCH%' ^
    -ex 'ghidra trace connect \"localhost:%OPT_REMOTE_PORT%\"' ^
    -ex 'ghidra trace start' ^
    -ex 'ghidra trace sync-enable' ^
    -ex 'set confirm on' ^
    -ex 'set pagination on'
) ELSE (
  set cmd=TERM='%TERM%' '%OPT_GDB_PATH%' ^
    -q ^
    -ex 'set pagination off' ^
    -ex 'set confirm off' ^
    -ex 'show version' ^
    -ex 'python import ghidragdb' ^
    -ex 'set architecture %OPT_ARCH%' ^
    -ex 'file \"%OPT_TARGET_IMG%\"' ^
    -ex 'set args %OPT_TARGET_ARGS%' ^
    -ex 'ghidra trace connect \"localhost:%OPT_REMOTE_PORT%\"' ^
    -ex 'ghidra trace start' ^
    -ex 'ghidra trace sync-enable' ^
    -ex '%OPT_START_CMD%' ^
    -ex 'set confirm on' ^
    -ex 'set pagination on'
)

"%OPT_SSH_PATH%" "-R%OPT_REMOTE_PORT%:%GHIDRA_TRACE_RMI_ADDR%" -t %OPT_EXTRA_SSH_ARGS% "%OPT_HOST%" "%cmd%"
