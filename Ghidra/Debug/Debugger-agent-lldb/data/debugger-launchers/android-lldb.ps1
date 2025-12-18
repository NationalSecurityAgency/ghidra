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
#@title lldb Android
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
#@help lldb#android
#@depends Debugger-rmi-trace
#@enum StartCmd:str "process launch" "process launch --stop-at-entry"
#@arg :file "Image" "The target binary executable image"
#@env OPT_TARGET_ARGS:str="" "Arguments" "Command-line arguments to pass to the target"
#@env OPT_DEVICE:str="" "Device" "The device name (e.g. from 'adb devices')"
#@env OPT_PORT:str="9999" "Port" "The host's listening port"
#@env OPT_ARCH:str="" "Architecture" "Target architecture override"
#@env OPT_LLDB_PATH:file="lldb" "lldb command" "The path to lldb on the local system. Omit the full path to resolve using the system PATH."
#@env OPT_START_CMD:StartCmd="process launch" "Run command" "The lldb command to actually run the target."

. ..\support\lldbsetuputils.ps1

$pypathTrace = Ghidra-Module-PyPath "Debugger-rmi-trace"
$pypathLldb = Ghidra-Module-PyPath
$Env:PYTHONPATH = "$pypathLldb;$pypathTrace;$Env:PYTHONPATH"

$arglist = Compute-Lldb-Platform-Args `
    -TargetImage $args[0] `
    -TargetType "remote-android" `
    -TargetUrl "connect://$Env:OPT_DEVICE`:$Env:OPT_PORT" `
    -RmiAddress "$Env:GHIDRA_TRACE_RMI_ADDR"

Start-Process -FilePath $arglist[0] -ArgumentList $arglist[1..$arglist.Count] -NoNewWindow -Wait
