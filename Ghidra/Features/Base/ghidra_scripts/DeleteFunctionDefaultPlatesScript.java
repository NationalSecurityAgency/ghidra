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
// Removes default plate comments for all functions in the program or over a selection.
// " FUNCTION" is considered the default value for the plate comment.
//@category Update

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DeleteFunctionDefaultPlatesScript extends GhidraScript {

	private static String DEFAULT_PLATE = " FUNCTION";

	@Override
	public void run() throws Exception {

		AddressSetView set = currentProgram.getMemory();
		if (currentSelection != null && !currentSelection.isEmpty()) {
			set = currentSelection;
		}
		int updateCount = 0;
		FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(set, true);
		while (iter.hasNext()) {
			Function function = iter.next();
			String[] comment = function.getCommentAsArray();
			if (comment.length == 1 && comment[0].equals(DEFAULT_PLATE)) {
				function.setComment(null);
				++updateCount;
			}
		}
		if (updateCount > 0) {
			String cmt = updateCount > 1 ? "comments" : "comment";
			println("Removed " + updateCount + " default plate " + cmt + ".");
		}
		else {
			println("Did not find any default plate comments.");
		}
	}
}
