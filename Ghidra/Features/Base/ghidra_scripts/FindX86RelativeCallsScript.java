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
// Search for the start of X86 relative call instructions, look at the potential target and
// and if the function is valid, then disassemble and create a function at the target.
//
// Your mileage may vary!  This should only be run after existing code has been found.
// The results should be checked for validity.
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;

public class FindX86RelativeCallsScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		Address addr = currentProgram.getMemory().getMinAddress();
		PseudoDisassembler pdis = new PseudoDisassembler(currentProgram);

		AddressSetView execSet = currentProgram.getMemory().getExecuteSet();
		AddressSet disSet = new AddressSet();

		while (addr != null) {
			addr = this.find(addr, (byte) 0xe8);
			if (addr == null) {
				break;
			}

			if (execSet.isEmpty() || execSet.contains(addr)) {
				CodeUnit cu = currentProgram.getListing().getUndefinedDataAt(addr);
				if (cu != null) {
					PseudoInstruction instr = pdis.disassemble(addr);

					Address target = instr.getAddress(0);

					if (currentProgram.getMemory().contains(target) &&
						(execSet.isEmpty() || execSet.contains(target))) {
						// println ("e8 call " + addr + " -> "  + target);

						// also disassemble from this call.
						// This will only get a partial function, so maybe it would be better not to do this
						if (currentProgram.getFunctionManager().getFunctionAt(target) != null) {
							disassemble(addr);
							disSet.add(addr);
						}

						//  There should be more checks done here on the validity.
						//  maybe does the potential function at target start like other functions
						//  that have already been defined.
						Instruction realinstr =
							currentProgram.getListing().getInstructionAt(target);
						if (realinstr == null) {
							boolean isvalid = pdis.isValidSubroutine(target, true);
							if (isvalid) {
								// println("    found");
								disassemble(target);
								disSet.add(target);
								createFunction(target, null);
							}
						}
					}
				}
			}
			addr = addr.add(1);
		}

		show("X86 Relative Calls", disSet);
	}
}
