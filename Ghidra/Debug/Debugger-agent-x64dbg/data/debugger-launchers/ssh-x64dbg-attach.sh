#!/usr/bin/env bash
## ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##
#@title x64dbg attach via ssh (shell)
#@desc <html><body width="300px">
#@desc   <h3>Launch with <tt>x64dbg</tt> via <tt>ssh</tt></h3>
#@desc   <p>
#@desc     This will start <tt>x64dbg</tt> on the remote system via a Python interpreter.
#@desc     For setup instructions, press <b>F1</b>.
#@desc   </p>
#@desc </body></html>
#@menu-group x64dbg
#@icon icon.debugger
#@help x64dbg#ssh
#@depends Debugger-rmi-trace
#@env OPT_TARGET_PID:int=0 "Process id" "The target process id"
#@env OPT_TARGET_DIR:str="" "Dir" "Initial directory"
#@env OPT_SSH_PATH:file="ssh" "ssh command" "The path to ssh on the local system. Omit the full path to resolve using the system PATH."
#@env OPT_HOST:str="localhost" "[User@]Host" "The hostname or user@host"
#@env OPT_REMOTE_PORT:int=12345 "Remote Trace RMI Port" "A free port on the remote end to receive and forward the Trace RMI connection."
#@env OPT_EXTRA_SSH_ARGS:str="" "Extra ssh arguments" "Extra arguments to pass to ssh. Use with care."
#@env OPT_X64DBG_EXE:file="C:\\Software\\release\\x64\\x64dbg.exe" "Path to x64dbg.exe" "Path to x64dbg.exe (or equivalent)."
#@env OPT_PYTHON_EXE:file!="python" "Python command" "The path to the Python 3 interpreter. Omit the full path to resolve using the system PATH."
#@env OPT_PYTHON_ARGS:str="" "python cmd args" "Arguments passed to python (versus the target)"

. ../support/x64dbgsetuputils.sh

x64dbg_exe=$(echo $OPT_X64DBG_EXE | sed 's/\\/\\\\/g')

OPT_OS_WINDOWS=true

function launch-x64dbg-scp() {
	local -a scpargs
	compute-scp-args "../support/local-x64dbg-attach.py"

	"${scpargs[@]}"
}

function launch-x64dbg-ssh() {
	local -a sshargs
	compute-ssh-args true "$OPT_PYTHON_EXE -i $OPT_PYTHON_ARGS .\\local-x64dbg-attach.py localhost:$OPT_REMOTE_PORT $OPT_TARGET_PID $x64dbg_exe"

	"${sshargs[@]}"
}

version=$(get-ghidra-version)

function do-installation() {
	local -a pipargs
	compute-x64dbg-pipinstall-args "'-f'" "os.environ['HOME']" "'ghidraxdbg>=$version'"
	local -a sshargs
	compute-ssh-args false "${pipargs[@]}"

	"${sshargs[@]}"
}

launch-x64dbg-scp
launch-x64dbg-ssh "$@"
if check-result-and-prompt-mitigation $? "
It appears ghidraxdbg is missing from the remote system. This can happen if you
forgot to install the required package. This can also happen if you installed
the packages to a different Python environment than is being used by the
remote's x64dbg.

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
" "Would you like to install 'ghidraxdbg>=$version'?"; then

	echo "Copying Wheels to $OPT_HOST"
	if ! mitigate-scp-pymodules "Debugger-rmi-trace" "<SELF>"; then
		exit 1
	fi

	echo "Installing Wheels into python"
	do-installation
fi
