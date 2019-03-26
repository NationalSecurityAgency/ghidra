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
// Generate WARNING Bookmarks on instructions which have unimplemented pcode.
// Similar to disassembler's built-in marking but allows for refresh after 
// language update.
// @category sleigh
import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;

public class MarkUnimplementedPcode extends GhidraScript {

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			return;
		}
		AddressSetView set = currentSelection;
		if (set == null || set.isEmpty()) {
			set = currentProgram.getMemory().getExecuteSet();
		}

		Disassembler.clearUnimplementedPcodeWarnings(currentProgram, set, monitor);

		int completed = 0;
		monitor.initialize(set.getNumAddresses());

		InstructionIterator instructions = currentProgram.getListing().getInstructions(set, true);
		while (instructions.hasNext()) {
			monitor.checkCanceled();
			Instruction instr = instructions.next();

			PcodeOp[] pcode = instr.getPcode();
			if (pcode != null && pcode.length == 1 &&
				pcode[0].getOpcode() == PcodeOp.UNIMPLEMENTED) {
				markUnimplementedPcode(instr);
			}

			completed += instr.getLength();
			if ((completed % 1000) == 0) {
				monitor.setProgress(completed);
			}
		}

	}

	private void markUnimplementedPcode(Instruction instr) {
		currentProgram.getBookmarkManager().setBookmark(instr.getAddress(), BookmarkType.WARNING,
			Disassembler.UNIMPL_BOOKMARK_CATEGORY,
			"Instruction pcode is unimplemented: " + instr.getMnemonicString());
	}
}
