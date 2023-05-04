/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Assigns custom storage for params of a golang function to match golang's abi-internal
// register-based calling convention, or abi0 (all stack based) if abi-internal is not 
// specified for the arch.
//@category Functions
//@menupath Tools.Fix Golang Function Param Storage 
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.golang.GoFunctionFixup;
import ghidra.app.util.bin.format.golang.GoVer;
import ghidra.program.model.listing.Function;

public class FixupGolangFuncParamStorageScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Function func;
		if (currentAddress == null || (func = getFunctionContaining(currentAddress)) == null) {
			return;
		}
		GoVer goVersion = GoVer.fromProgramProperties(currentProgram);
		if ( goVersion == GoVer.UNKNOWN ) {
			List<GoVer> versions = List.of(GoVer.values());
			goVersion =
				askChoice("Golang Version", "What is the golang version?", versions, GoVer.UNKNOWN);
		}
		println("Fixing param storage for function %s@%s".formatted(func.getName(),
			func.getEntryPoint()));
		GoFunctionFixup.fixupFunction(func, goVersion);
	}

}
