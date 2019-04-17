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
//Assemble a single instruction, overwriting the one at the cursor.
//@category Assembly

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;

/**
 * This is a demonstration script to show how to use the assembler in scripts. The GUI assembler is
 * accessed using CTRL-SHIFT-G.
 */
public class AssembleScript extends GhidraScript {
	@Override
	public void run() throws Exception {
		monitor.setMessage("Constructing Assember");
		// First, obtain an assembler bound to the current program.
		// If a suitable assembler has not yet been build, this will take some time to build it.
		Assembler asm = Assemblers.getAssembler(currentProgram);

		monitor.setMessage("Awaiting Input");
		// Put the current instruction text in by default.
		Instruction ins = getInstructionAt(currentAddress);
		String cur = "";
		if (ins != null) {
			cur = ins.toString();
		}

		// Now present the prompt and assemble the given text.
		// The assembler will patch the result into the bound program.
		asm.assemble(currentAddress, askString("Assemble", "Type an instruction", cur));
	}
}
