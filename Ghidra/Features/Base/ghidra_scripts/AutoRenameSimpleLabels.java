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
//A ghidra script that renames simple functions to assist in the propogating of information
//through the disassembly.
//It converts functions which are only 1 instuction long and that instruction is return or branch/jump
// 
//For instance a simple return function will be labeled ret_XXXX, where XXXX is the address
//Also, a function that branches to another label will be renamed to dest_branch_XXXX, where dest is
//destination label and XXXX is the address
//Repeatable comments from these functions are propogated up from destination functions.
//
//Symbols are replaced if they are DEFAULT or ANALYSIS only (they are not replaced if the symbol is
//USER_DEFINED or IMPORTED).
// 
//Feel free to add any other rules!
// 
//@category Symbol

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.*;

/*
 * AutoRenameSimpleLabels
 * 
 * Renames labels that are just RET or branch instructions
 */
public class AutoRenameSimpleLabels extends GhidraScript {

	boolean isDefaultName(Symbol symbol) {
		return symbol.getSource() == SourceType.DEFAULT ||
			symbol.getSource() == SourceType.ANALYSIS;
	}

	@Override
	public void run() throws Exception {
		String tmpString = "\nScript: AutoRenameSimpleLabels() \n";

		//get listing of symbols
		SymbolIterator iter = currentProgram.getSymbolTable().getAllSymbols(true);

		String newName;
		int modified_count = 0;

		while (iter.hasNext() && !monitor.isCancelled()) {

			//get this instruction's info
			Symbol s = iter.next();
			Address startAddr = s.getAddress();

			// read the instruction type and operand
			Instruction inst = getInstructionAt(startAddr);
			if (inst == null) {
				continue;
			}
			FlowType flow = inst.getFlowType();
			String operand = " ";
			try {
				operand = inst.getDefaultOperandRepresentation(0);
			}
			catch (NullPointerException excp) {
				// not sure why, but we get this sometime
				//println ("Lousy null pointer at " + startAddr.toString(false).toUpperCase());
				continue;
			}

			//println("instruction @ " + startAddr.toString(false).toUpperCase() + " type= " + flow.toString() + " operand=" + operand);

			if (flow.isFallthrough()) {
				// the instruction falls through, so this function is just an entry point
				continue;
			}

			if (flow.isConditional()) {
				//println("conditional instruction, ignore");
				continue;
			}

			//println("instruction @ " + startAddr.toString(false).toUpperCase() + " type= " + flow.toString() + " operand= " + operand);

			if (flow.isTerminal()) {
				//println("terminal instruction at " + startAddr.toString(false).toUpperCase());
				newName = "ret_" + startAddr.toString(false).toUpperCase();

				if (s.getName().compareToIgnoreCase(newName) == 0) {
					// same name so ignore
					continue;
				}
				if (!isDefaultName(s)) {
					// user has already labeled this function so don't overwrite their hard work
					continue;
				}
				println("Renaming RET @ " + startAddr.toString(false).toUpperCase() + ": " +
					s.getName() + " to " + newName);
				s.setName(newName, SourceType.ANALYSIS);
				modified_count += 1;
			}
			else if (flow.isJump()) {
				//println("unconditional jump instruction at " + startAddr.toString(false).toUpperCase() );
				newName = "branch_" + startAddr.toString(false).toUpperCase() + "_" + operand;
				// NOTE: can't end on a hex number for operands that start with 'LAB_CODE' ??
				// so append '_' 
				// ???

				//Symbol operand_sym = currentProgram.getSymbolTable().getSymbol(operand);
				if (inst.getOperandReferences(0) == null ||
					inst.getOperandReferences(0).length == 0) {
					continue;
				}
				Reference ref = inst.getOperandReferences(0)[0];
				Symbol operand_sym = currentProgram.getSymbolTable().getSymbol(ref);
				if (operand_sym == null) {
					continue;
				}
				Address operand_addr = operand_sym.getAddress();

				if (s.getName().compareToIgnoreCase(newName) != 0) {
					if (isDefaultName(s)) {

						// let's also make sure that it isn't an branch to itself
						if (operand_addr == startAddr) {
							// caught an infinite loop
							continue;
						}

						println("Renaming BR @ " + startAddr.toString(false).toUpperCase() + ": " +
							s.getName() + " to " + newName);
						s.setName(newName, SourceType.ANALYSIS);
						modified_count += 1;
					}
				}

				// now also propogate the repeatable comment up as well

				String comment = currentProgram.getListing().getComment(CodeUnit.REPEATABLE_COMMENT,
					operand_addr);
				if (comment != null) {
					if (currentProgram.getListing().getComment(CodeUnit.REPEATABLE_COMMENT,
						startAddr) == null) {
						//println("updating comment for " + operand +" is " + comment);
						currentProgram.getListing().setComment(startAddr,
							CodeUnit.REPEATABLE_COMMENT, comment);
					}
				}
			}
		}

		println("Modified a total of " + modified_count + " entries");
	}

}
