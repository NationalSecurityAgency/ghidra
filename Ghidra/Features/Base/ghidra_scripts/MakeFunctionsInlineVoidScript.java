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
// Mark all functions within the current selection as inline with a return type of void
//
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;

public class MakeFunctionsInlineVoidScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		int cnt = 0;
		if (currentSelection != null && !currentSelection.isEmpty()) {
			FunctionIterator fnIter =
				currentProgram.getFunctionManager().getFunctions(currentSelection, true);
			while (fnIter.hasNext()) {
				updateFunction(fnIter.next());
				++cnt;
			}
		}
		else if (currentLocation != null) {
			Function func =
				currentProgram.getFunctionManager().getFunctionContaining(
					currentLocation.getAddress());
			if (func != null) {
				updateFunction(func);
				++cnt;
			}
		}
		setToolStatusMessage(cnt + " function(s) set as inline void", false);
	} // end of run
//	 any functions that are called by run

	private void updateFunction(Function func) throws InvalidInputException {
		func.setInline(true);
		func.setReturnType(DataType.VOID, SourceType.USER_DEFINED);
	}
}
