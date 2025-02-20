::@timeout 60000
::@title lldb via ssh
::@image-opt env:OPT_TARGET_IMG
::@desc <html><body width="300px">
::@desc   <h3>Launch with <tt>lldb</tt> via <tt>ssh</tt></h3>
::@desc   <p>
::@desc     This will launch the target on a remote machine using <tt>lldb</tt> via <tt>ssh</tt>.
::@desc     For setup instructions, press <b>F1</b>.
::@desc   </p>
::@desc </body></html>
::@menu-group remote
::@icon icon.debugger
::@help TraceRmiLauncherServicePlugin#lldb_ssh
::@enum StartCmd:str "process launch" "process launch --stop-at-entry"
::@enum Endian:str auto big little
::@env OPT_TARGET_IMG:str="" "Image" "The target binary executable image on the remote system"
::@env OPT_TARGET_ARGS:str="" "Arguments" "Command-line arguments to pass to the target"
::@env OPT_SSH_PATH:file!="ssh" "ssh command" "The path to ssh on the local system. Omit the full path to resolve using the system PATH."
::@env OPT_HOST:str="localhost" "[User@]Host" "The hostname or user@host"
::@env OPT_REMOTE_PORT:int=12345 "Remote Trace RMI Port" "A free port on the remote end to receive and forward the Trace RMI connection."
::@env OPT_EXTRA_SSH_ARGS:str="" "Extra ssh arguments" "Extra arguments to pass to ssh. Use with care."
::@env OPT_LLDB_PATH:str="lldb" "lldb command" "The path to lldb on the remote system. Omit the full path to resolve using the system PATH."
::@env OPT_START_CMD:StartCmd="process launch" "Run command" "The lldb command to actually run the target."
::@env OPT_ARCH:str="x86_64" "Architecture" "Target architecture"

@echo off

IF "%OPT_TARGET_ARGS%" == "" (
  set cmd=TERM='%TERM%' '%OPT_LLDB_PATH%' ^
	-o 'version' ^
	-o 'script import ghidralldb' ^
    -o 'settings set target.default-arch %OPT_ARCH%' ^
    -o 'ghidra trace connect \"localhost:%OPT_REMOTE_PORT%\"' ^
    -o 'target create \"%OPT_TARGET_IMG%\"' ^
    -o 'ghidra trace start' ^
    -o 'ghidra trace sync-enable' ^
	-o '%OPT_START_CMD%'
) ELSE (
  set cmd=TERM='%TERM%' '%OPT_LLDB_PATH%' ^
	-o 'version' ^
	-o 'script import ghidralldb' ^
    -o 'settings set target.default-arch %OPT_ARCH%' ^
    -o 'ghidra trace connect \"localhost:%OPT_REMOTE_PORT%\"' ^
    -o 'target create \"%OPT_TARGET_IMG%\"' ^
	-o 'settings set target.run-args %OPT_TARGET_ARGS%' ^
    -o 'ghidra trace start' ^
    -o 'ghidra trace sync-enable' ^
	-o '%OPT_START_CMD%'
)

"%OPT_SSH_PATH%" "-R%OPT_REMOTE_PORT%:%GHIDRA_TRACE_RMI_ADDR%" -t %OPT_EXTRA_SSH_ARGS% "%OPT_HOST%" "%cmd%"
