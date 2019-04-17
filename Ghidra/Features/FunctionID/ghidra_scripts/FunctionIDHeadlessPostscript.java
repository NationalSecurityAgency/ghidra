/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
//Fixes switch statements and checks number/size of functions after
//analysis has run in headless mode whilst importing a large number of
//.obj files for use in creating a Function ID library.
//@category FunctionID
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;

public class FunctionIDHeadlessPostscript extends GhidraScript {
	public static final int MINIMUM_FUNCTION_SIZE_IN_BYTES = 6;

	@Override
	protected void run() throws Exception {
		runScript("FixSwitchStatementsWithDecompiler.java");

		FunctionManager functionManager = currentProgram.getFunctionManager();
		int functionCount = functionManager.getFunctionCount();
		if (functionCount == 0) {
			printerr(currentProgram.getDomainFile().getPathname() + " has no functions");

			// keep the functionless domain object for now in case user wants to
			// inspect why analysis failed (or didn't)

//			getState().addEnvironmentVar(GhidraScript.SCRIPT_SET_CONTINUATION_STATUS,
//				HeadlessContinuationOption.ABORT_AND_DELETE);
			return;
		}
		FunctionIterator functions = functionManager.getFunctions(true);
		for (Function function : functions) {
			AddressSetView body = function.getBody();
			if (body.getNumAddresses() >= MINIMUM_FUNCTION_SIZE_IN_BYTES) {
				// at least one meets threshold; everything is OK
				return;
			}
		}
		printerr(currentProgram.getDomainFile().getPathname() +
			" has no normal-sized functions (>= " + MINIMUM_FUNCTION_SIZE_IN_BYTES + " bytes long)");

		// keep the functionless domain object for now in case user wants to
		// inspect why analysis failed (or didn't)

//		getState().addEnvironmentVar(GhidraScript.SCRIPT_SET_CONTINUATION_STATUS,
//			HeadlessContinuationOption.ABORT_AND_DELETE);
	}
}
