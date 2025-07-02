#@title gdb via ssh
#@image-opt arg:1
#@desc <html><body width="300px">
#@desc   <h3>Launch with <tt>gdb</tt> via <tt>ssh</tt></h3>
#@desc   <p>
#@desc     This will launch the target on a remote machine using <tt>gdb</tt> via <tt>ssh</tt>.
#@desc     For setup instructions, press <b>F1</b>.
#@desc   </p>
#@desc </body></html>
#@menu-group gdb
#@icon icon.debugger
#@help gdb#ssh
#@depends Debugger-rmi-trace
#@enum StartCmd:str run start starti
#@enum Endian:str auto big little
#@arg :str "Image" "The target binary executable image on the remote system"
#@env OPT_TARGET_ARGS:str="" "Arguments" "Command-line arguments to pass to the target"
#@env OPT_SSH_PATH:file="ssh" "ssh command" "The path to ssh on the local system. Omit the full path to resolve using the system PATH."
#@env OPT_HOST:str="localhost" "[User@]Host" "The hostname or user@host"
#@env OPT_REMOTE_PORT:int=12345 "Remote Trace RMI Port" "A free port on the remote end to receive and forward the Trace RMI connection."
#@env OPT_EXTRA_SSH_ARGS:str="" "Extra ssh arguments" "Extra arguments to pass to ssh. Use with care."
#@env OPT_GDB_PATH:str="gdb" "gdb command" "The path to gdb on the remote system. Omit the full path to resolve using the system PATH."
#@env OPT_START_CMD:StartCmd="starti" "Run command" "The gdb command to actually run the target."
#@env OPT_ARCH:str="i386:x86-64" "Architecture" "Target architecture"
#@env OPT_ENDIAN:Endian="auto" "Endian" "Target byte order"

. ..\support\gdbsetuputils.ps1

$arglist = Compute-Gdb-Usermode-Args -TargetImage $args[0] -RmiAddress "localhost:$Env:OPT_REMOTE_PORT"
$sshargs = Compute-Ssh-Args $arglist True

$sshproc = Start-Process -FilePath $sshargs[0] -ArgumentList $sshargs[1..$sshargs.Count] -NoNewWindow -Wait -PassThru

$version = Get-Ghidra-Version
$answer = Check-Result-And-Prompt-Mitigation $sshproc @"
It appears ghidragdb is missing from the remote system. This can happen if you
forgot to install the required package. This can also happen if you installed
the packages to a different Python environment than is being used by the
remote's gdb.

This script is about to offer automatic resolution. If you'd like to resolve
this manually, answer no to the next question and then see Ghidra's help by
pressing F1 in the dialog of launch parameters.

WARNING: Answering yes to the next question will invoke pip to try to install
missing or incorrectly-versioned dependencies. It may attempt to find packages
from the PyPI mirror configured on the REMOTE system. If you have not configured
one, it will connect to the official one.

WARNING: We invoke pip with the --break-system-packages flag, because some
debuggers that embed Python (gdb, lldb) may not support virtual environments,
and so the packages must be installed to your user environment.

NOTE: This will copy Python wheels into the HOME directory of the user on the
remote system. You may be prompted to authenticate a few times while packages
are copied and installed.

NOTE: Automatic resolution will cause this session to terminate. When it has
finished, try launching again.
"@ "Would you like to install 'ghidragdb>=$version'?"

if ($answer) {
	Write-Host "Copying Wheels to $Env:OPT_HOST"
	Mitigate-Scp-PyModules "Debugger-rmi-trace" "<SELF>"

	Write-Host "Installing Wheels into GDB's embedded Python"
	$arglist = Compute-Gdb-PipInstall-Args "'-f'" "os.environ['HOME']" "'ghidragdb>=$version'"
	$sshargs = Compute-Ssh-Args $arglist False
	Start-Process -FilePath $sshargs[0] -ArgumentList $sshargs[1..$sshargs.Count] -NoNewWindow -Wait
}
