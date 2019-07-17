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
//Hashes the function at the current address using the FID Service.
//@keybinding Shift-H
//@category FunctionID
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.service.FidService;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class FIDHashCurrentFunction extends GhidraScript {
	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			printerr("No current program");
			return;
		}
		if (currentAddress == null) {
			printerr("No current address (?)");
			return;
		}
		FunctionManager functionManager = currentProgram.getFunctionManager();
		Function function = functionManager.getFunctionContaining(currentAddress);
		if (function == null) {
			printerr("No current function");
			return;
		}
		FidService service = new FidService();
		FidHashQuad hashFunction = service.hashFunction(function);
		if (hashFunction == null) {
			printerr("Function too small");
			return;
		}
		println("FID Hash for " + function.getName() + " at " + function.getEntryPoint() + ": " +
			hashFunction.toString());
	}
}
