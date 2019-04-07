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
//Test assembly of the instruction under the cursor.
//@category Assembly
//@keybinding CTRL-H

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.program.model.listing.Instruction;

public class AssembleCheckDevScript extends AssemblyThrasherDevScript {
	@Override
	protected void run() throws Exception {
		monitor.setMessage("Constructing Assember");
		AllMatchByTextSelector checker = new AllMatchByTextSelector();
		Assembler asm = Assemblers.getAssembler(currentProgram, checker);
		Instruction ins = currentProgram.getListing().getInstructionAt(currentAddress);
		if (ins != null) {
			monitor.setMessage("Assembling");
			checker.setExpected(ins);
			println("Assembling " + ins.getAddress() + ": " + ins);
			try {
				asm.assemble(ins.getAddress(), ins.toString());
			}
			catch (Accept e) {
				// Do nothing.
			}
			// Let other exceptions smash on
		}
	}
}
