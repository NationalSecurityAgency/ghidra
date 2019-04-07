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
// Script requests current variable name and desired new name.
// It then iterates through all functions, renaming the variable.
//
// Note: Script does not verify that no other variable within the
//       function is already using the new name.
//
//@category CustomerSubmission.Search

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;

public class RenameVariable extends GhidraScript {

	@Override
	public void run() throws Exception {

		// get current variable name
		String curName = askString("Current variable name", "Current Name");
		if (curName == null)
			return;

		// get desired new variable name
		String newName = askString("New variable name", "New Name");
		if (newName == null)
			return;

		// initialize count and get function iterator
		int count = 0;
		FunctionIterator funcs = currentProgram.getListing().getFunctions(true);

		// iterate through all functions in current program's listing
		while (funcs.hasNext() && !monitor.isCancelled()) {

			// get current function and list of associated variables
			Function f = funcs.next();
			Variable[] vars = f.getLocalVariables();

			// iterate through all variables for current function
			for (int i = 0; i < vars.length; i++) {
				Variable v = vars[i];
				if (v.getName().equals(curName)) {
					println(f.getName() + "::" + v.getName());
					v.setName(newName, SourceType.USER_DEFINED);
					count = count + 1;
				}
			}
		}

		println("Found " + count + " instances of " + curName);
	}
}
