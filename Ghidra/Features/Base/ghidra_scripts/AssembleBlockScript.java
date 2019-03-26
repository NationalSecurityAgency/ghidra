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
//Assemble hard-coded block of instructions.
//@category Assembly

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.script.GhidraScript;

/**
 * This is a demonstration script to show how to use the assembler to assemble a block of
 * instructions.
 */
public class AssembleBlockScript extends GhidraScript {
	@Override
	protected void run() throws Exception {
		monitor.setMessage("Constructing Assembler");
		// First, obtain an assembler bound to the current program.
		Assembler asm = Assemblers.getAssembler(currentProgram);

		monitor.setMessage("Assembling");
		// Now assemble a block. A block can be given as an array of strings, or a string of
		// newline-separated instructions.
		// This will patch each resulting instruction into the bound program in sequence.
		asm.assemble(currentAddress, //
			"ADD [RBX],BL", //
			"JMP 0x34", //
			"SCASB.REPE RDI");
	}
}
