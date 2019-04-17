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
// Script requests target and replacement strings.
// It then iterates through most comments in the program, replacing
// the target string with the specified replacement string.
// Comments scanned include:
//    - EOL
//    - Plate
//    - Post
//    - Pre
//    - Function (plate)
//    - Function repeatable
//    - Local variable (stack and register)
//
// Notes:
//    - Script scans every address within the program, so it is slow.
//    - Script doesn't scan param comments.
//
//@category CustomerSubmission.Search

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;

public class ReplaceInComments extends GhidraScript {

	@Override
	public void run() throws Exception {

		// get target string
		String tgtStr = askString("Target string", "Target String");
		if (tgtStr == null)
			return;

		// get replacement string
		String replStr = askString("Replacement string", "Replacement String");
		if (replStr == null)
			return;

		// initialize count and get memory blocks
		int count = 0;
		MemoryBlock[] blocks = getMemoryBlocks();

		// iterate through all memory blocks in current program
		for (int i = 0; i < blocks.length; i++) {

			// iterate through all addresses for current block
			MemoryBlock m = blocks[i];
			println("Scanning block beginning at 0x" + m.getStart().toString());
			Address a;
			for (a = m.getStart(); !a.equals(m.getEnd().add(1)); a = a.add(1)) {

				if (monitor.isCancelled())
					return;
				String curComment, newComment;

				// replace target with replacement within each comment at address

				curComment = getEOLComment(a);
				if (curComment != null) {
					newComment = curComment.replaceAll(tgtStr, replStr);
					if (!curComment.equals(newComment)) {
						println("   0x" + a.toString() + ":  " + newComment);
						setEOLComment(a, newComment);
						count = count + 1;
					}
				}

				curComment = getPlateComment(a);
				if (curComment != null) {
					newComment = curComment.replaceAll(tgtStr, replStr);
					if (!curComment.equals(newComment)) {
						println("   0x" + a.toString() + ":  " + newComment);
						setPlateComment(a, newComment);
						count = count + 1;
					}
				}

				curComment = getPostComment(a);
				if (curComment != null) {
					newComment = curComment.replaceAll(tgtStr, replStr);
					if (!curComment.equals(newComment)) {
						println("   0x" + a.toString() + ":  " + newComment);
						setPostComment(a, newComment);
						count = count + 1;
					}
				}

				curComment = getPreComment(a);
				if (curComment != null) {
					newComment = curComment.replaceAll(tgtStr, replStr);
					if (!curComment.equals(newComment)) {
						println("   0x" + a.toString() + ":  " + newComment);
						setPreComment(a, newComment);
						count = count + 1;
					}
				}
			}
		}

		// iterate through all functions in current program's listing
		FunctionIterator funcs = currentProgram.getListing().getFunctions(true);
		println("Scanning function and local variable comments...");
		while (funcs.hasNext() && !monitor.isCancelled()) {

			// get current function and scan its comments
			Function f = funcs.next();
			String curComment, newComment;

			// function plate comment
			curComment = f.getComment();
			if (curComment != null) {
				newComment = curComment.replaceAll(tgtStr, replStr);
				if (!curComment.equals(newComment)) {
					println("   " + f.getName() + ".comment");
					f.setComment(newComment);
					count = count + 1;
				}
			}

			// function repeatable comment
			curComment = f.getRepeatableComment();
			if (curComment != null) {
				newComment = curComment.replaceAll(tgtStr, replStr);
				if (!curComment.equals(newComment)) {
					println("   " + f.getName() + ".repeatableComment");
					f.setRepeatableComment(newComment);
					count = count + 1;
				}
			}

			// iterate through all variable comments for current function
			Variable[] vars = f.getLocalVariables();
			for (int i = 0; i < vars.length; i++) {
				Variable v = vars[i];
				curComment = v.getComment();
				if (curComment != null) {
					newComment = curComment.replaceAll(tgtStr, replStr);
					if (!curComment.equals(newComment)) {
						println("   " + f.getName() + "::" + v.getName() + ":  " + newComment);
						v.setComment(newComment);
						count = count + 1;
					}
				}
			}
		}

		println("Comments changed:  " + count);
	}
}
