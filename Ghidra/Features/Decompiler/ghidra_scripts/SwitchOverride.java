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
//Override indirect jump destinations
//
// This script allows the user to manually specify the destinations of an indirect jump (switch)
// to the decompiler, if it can't figure out the destinations itself or does so incorrectly.
// To use, create a selection that contains:
//     the (one) instruction performing the indirect jump to override
//     other instructions whose addresses are interpreted as destinations of the switch
// then run this script
//
//  You can also pre-add the COMPUTED_JUMP references to the branch instruction before running the
//  script, and simply put the cursor on the computed branching instruction.
//@category Repair

import java.util.ArrayList;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.*;

public class SwitchOverride extends GhidraScript {

	private Address collectSelectedJumpData(Listing listing,AddressSetView select,ArrayList<Address> destlist) {
		Address branchind = null;
		AddressIterator iter = select.getAddresses(true);
		while(iter.hasNext()) {
			Address addr = iter.next();
			Instruction inst = listing.getInstructionAt(addr);
			if (isComputedBranchInstruction(inst)) {
				branchind = addr;
			}
			else if (inst != null) {
				destlist.add(addr);
			}
		}
		return branchind;
	}
	
	private Address collectPointJumpData(Listing listing,
			Address addr, ArrayList<Address> destlist) {
		Address branchind = null;
		
		// current location must be a callfixup, or an indirect Jump
		Instruction instr = currentProgram.getListing().getInstructionAt(addr);
		
		if (isComputedBranchInstruction(instr)) {
			branchind = addr;
		}
		
		// add any jump references already added
		Reference[] referencesFrom = instr.getReferencesFrom();
		for (Reference reference : referencesFrom) {
			RefType referenceType = reference.getReferenceType();
			if (referenceType.isJump()) {
				destlist.add(reference.getToAddress());
			}
		}
		
		return branchind;
	}

	private boolean isComputedBranchInstruction(Instruction instr) {
		if (instr == null) {
			return false;
		}
		
		FlowType flowType = instr.getFlowType();
		
		if (flowType == RefType.COMPUTED_JUMP) {
			return true;
		}
		if (flowType.isCall()) {
			// is it a callfixup?
			Reference[] referencesFrom = instr.getReferencesFrom();
			for (Reference reference : referencesFrom) {
				if (reference.getReferenceType().isCall()) {
					Function func = currentProgram.getFunctionManager().getFunctionAt(reference.getToAddress());
					if (func != null && func.getCallFixup() != null) {
						return true;
					}
				}
			}
		}
		return false;
	}

	
	@Override
	public void run() throws Exception {
		ArrayList<Address> destlist = new ArrayList<Address>();
		Address branchind = null;
		
		if (currentSelection != null && !currentSelection.isEmpty()) {
			branchind = collectSelectedJumpData(currentProgram.getListing(),currentSelection,destlist);
		} else {
			branchind = collectPointJumpData(currentProgram.getListing(),currentLocation.getAddress(),destlist);
		}
		
		if (branchind==null) {
			println("Please highlight or place the cursor on the instruction performing the computed jump");
			return;
		}
		if (destlist.size()==0) {
			println("Please highlight destination instructions in addition to instruction performing switch");
			println(" Or put CONDITIONAL_JUMP destination references at the branching instruction");
			return;
		}
		Function function = this.getFunctionContaining(branchind);
		if (function==null) {
			println("Computed jump instruction must be in a Function body.");
			return;
		}
		
		Instruction instr = currentProgram.getListing().getInstructionAt(branchind);
		for (Address address : destlist) {
			instr.addOperandReference(0, address, RefType.COMPUTED_JUMP, SourceType.USER_DEFINED);
		}

		// Allocate an override jumptable
		JumpTable jumpTab = new JumpTable(branchind,destlist,true);
		jumpTab.writeOverride(function);
		
		// fixup the body now that there are jump references
		CreateFunctionCmd.fixupFunctionBody(currentProgram, function, monitor);
	}
}
