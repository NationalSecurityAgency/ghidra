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
. $Env:MODULE_Debugger_rmi_trace_HOME\data\support\setuputils.ps1

function Compute-X64dbg-PipInstall-Args {
	$argvpart = $args -join ", "
	$arglist = @("$Env:OPT_PYTHON_EXE -c `"")
	$arglist+=("import os, sys, runpy")
	$arglist+=("sys.argv=['pip', 'install', '--force-reinstall', $argvpart]")
	$arglist+=("os.environ['PIP_BREAK_SYSTEM_PACKAGE']='1'")
	$arglist+=("runpy.run_module('pip', run_name='__main__')")

	return $arglist
}
