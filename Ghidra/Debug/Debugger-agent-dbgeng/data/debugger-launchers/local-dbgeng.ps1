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
#@title dbgeng
#@image-opt env:OPT_TARGET_IMG
#@desc <html><body width="300px">
#@desc   <h3>Launch with <tt>dbgeng</tt></h3>
#@desc   <p>
#@desc     This will launch the target on the local machine using <tt>dbgeng</tt>.
#@desc     For setup instructions, press <b>F1</b>.
#@desc   </p>
#@desc </body></html>
#@menu-group dbgeng
#@icon icon.debugger
#@help dbgeng#local
#@depends Debugger-rmi-trace
#@env OPT_TARGET_IMG:file="" "Image" "The target binary executable image"
#@env OPT_TARGET_ARGS:str="" "Arguments" "Command-line arguments to pass to the target"
#@env OPT_PYTHON_EXE:file!="python" "Python command" "The path to the Python 3 interpreter. Omit the full path to resolve using the system PATH."
#@env OPT_PYTHON_ARGS:str="" "python cmd args" "Arguments passed to python (versus the target)"
#@env OPT_USE_DBGMODEL:bool=true "Use dbgmodel" "Load and use dbgmodel.dll if it is available."
#@env WINDBG_DIR:dir="" "Path to dbgeng.dll directory" "Path containing dbgeng and associated DLLS (if not Windows Kits)."

. ..\support\dbgsetuputils.ps1

function Compute-Python-Args {
	param($TempFile)
	
	$arglist = @("$Env:OPT_PYTHON_EXE")
	if ("$Env:OPT_PYTHON_ARGS" -ne "") {
		$arglist+=($Env:OPT_PYTHON_ARGS)
	}
	$arglist+=($TempFile)

	$arglist+=($Env:GHIDRA_TRACE_RMI_ADDR)
	$arglist+=($Env:OPT_USE_DBGMODEL)
	$arglist+=($Env:OPT_TARGET_IMG)

	if ("$Env:OPT_TARGET_ARGS" -ne "") {
		$arglist+=($Env:OPT_TARGET_ARGS)
	}
	return $arglist
}

$pypathTrace = Ghidra-Module-PyPath "Debugger-rmi-trace"
$pypathDbg = Ghidra-Module-PyPath
$Env:PYTHONPATH = "$pypathDbg;$pypathTrace;$Env:PYTHONPATH"

$tmpfile = "..\support\local-dbgeng.py"
$arglist = Compute-Python-Args -TempFile $tmpfile

Start-Process -FilePath $arglist[0] -ArgumentList $arglist[1..$arglist.Count] `
	-NoNewWindow -Wait
