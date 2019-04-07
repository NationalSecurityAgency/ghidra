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
// Generate WARNING Bookmarks CallOther PcodeOp's within an instructions Pcode.
// This is useful to find PsuedoOps that need to be implemented to yield better
// emulation or decompilation.
// @category sleigh

import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;

public class MarkCallOtherPcode extends GhidraScript {

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

			for (int i = 0; i < pcode.length; i++) {
				if (pcode[i].getOpcode() == PcodeOp.CALLOTHER) {
					markCallOtherPcode(instr, pcode[i]);
				}
			}

			completed += instr.getLength();
			if ((completed % 1000) == 0) {
				monitor.setProgress(completed);
			}
		}

	}

	private void markCallOtherPcode(Instruction instr, PcodeOp op) {
		currentProgram.getBookmarkManager().setBookmark(instr.getAddress(), BookmarkType.WARNING,
			"CallOther PcodeOp",
			currentProgram.getLanguage().getUserDefinedOpName((int) op.getInput(0).getOffset()));
	}
}
