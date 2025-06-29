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
// Removes dead plate comments for all functions in the program or over a selection.
// " DEAD" is considered the default value for the plate comment.
//@category Update

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class DeleteDeadDefaultPlatesScript extends GhidraScript {

	private static String DEAD_PLATE = " DEAD";

	@Override
	public void run() throws Exception {
		Listing listing = currentProgram.getListing();
		AddressSetView set = currentProgram.getMemory();
		if (currentSelection != null && !currentSelection.isEmpty()) {
			set = currentSelection;
		}

		int updateCount = 0;
		AddressIterator iter = listing.getCommentAddressIterator(CommentType.PLATE, set, true);
		while (iter.hasNext()) {
			Address addr = iter.next();
			CodeUnit cu = listing.getCodeUnitAt(addr);
			if (cu != null) {
				String[] comment = cu.getCommentAsArray(CommentType.PLATE);
				if (comment.length == 1 && comment[0].equals(DEAD_PLATE)) {
					cu.setComment(CommentType.PLATE, null);
					++updateCount;
				}
			}
		}
		if (updateCount > 0) {
			String cmt = updateCount > 1 ? "comments" : "comment";
			println("Removed " + updateCount + " default plate " + cmt + ".");
		}
		else {
			println("Did not find any dead plate comments.");
		}
	}
}
