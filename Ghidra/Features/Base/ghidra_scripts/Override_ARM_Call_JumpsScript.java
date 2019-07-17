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
// Given a selection that represents a function re-tag all calls that should be Jumps as a Jump.
//   Some compilers for the ARM use a typical (bl <x>)call instruction as a form of long jump.
//   The bl instruction is a branch and link, usually associated with a call.
//   The ARM language module has the ability to override the call instruction with a CALLOVERRIDE context.
//
//   There is one degenerate case, where somewhere in a function it jumps to the first instruction in a subroutine
//   while other locations really do call the location.
//
//   This script assumes good flow, that switch stmts are good.
//
//@category ARM

import ghidra.app.cmd.disassemble.SetFlowOverrideCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.util.Iterator;

public class Override_ARM_Call_JumpsScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		if (currentSelection == null || currentSelection.isEmpty()) {
			this.popup("All instructions in a single subroutine must be selected");
			return;
		}

		AddressSet funcsToClear = new AddressSet();
		AddressSet funcsToFix = new AddressSet();

		AddressSet locationsFixed = new AddressSet();

		Iterator<Function> fiter =
			currentProgram.getFunctionManager().getFunctionsOverlapping(currentSelection);
		if (!fiter.hasNext()) {
			this.popup("A single function must be defined within the selection");
			return;
		}

		Function func = fiter.next();
		if (fiter.hasNext()) {
			this.popup("Only ONE function allowed to be defined in the selection");
			return;
		}

		// branchSet will contain those addresses that need to be changed to a jump in this block
		AddressSet branchSet = new AddressSet();

		boolean isBad = false;
		SimpleBlockModel basicBlockModel = new SimpleBlockModel(currentProgram);
		CodeBlockIterator bbIter =
			basicBlockModel.getCodeBlocksContaining(currentSelection, monitor);

		while (bbIter.hasNext()) {
			CodeBlock bbBlock = bbIter.next();

			CodeBlockReferenceIterator bbDestRefIter = bbBlock.getDestinations(monitor);
			while (bbDestRefIter.hasNext()) {
				CodeBlockReference bbRef = bbDestRefIter.next();

				if (bbRef.getFlowType().isCall() &&
					currentSelection.contains(bbRef.getDestinationAddress())) {
					Instruction instr =
						currentProgram.getListing().getInstructionContaining(
							bbBlock.getMaxAddress());
					// must override at call location
					branchSet.addRange(instr.getMinAddress(), instr.getMinAddress());

					// don't clear functions that are jumped to if they are really the target of a call
					if (!bbRef.getDestinationAddress().equals(currentSelection.getMinAddress())) {
						// must clear function at destination
						funcsToClear.addRange(bbRef.getDestinationAddress(),
							bbRef.getDestinationAddress());
					}
					isBad = true;
				}
			}
		}

		if (!isBad) {
			popup("no bad call locations found");
			return;
		}

		// this is one bad one
		funcsToFix.addRange(func.getEntryPoint(), func.getEntryPoint());
		goTo(func.getEntryPoint());
		createSelection(funcsToFix);

		locationsFixed.add(branchSet);
		createHighlight(locationsFixed);

		// get rid of the bad functions
		AddressIterator aIter = funcsToClear.getAddresses(true);
		while (aIter.hasNext()) {
			Address addr = aIter.next();
			currentProgram.getFunctionManager().removeFunction(addr);

			createBookmark(addr, " Override ARM CALL to Jump fixer", "Removed Bogus function");
		}

		// for each branch location
		//    set CALLoverride
		//    clear/disassemble the instruction
		//    check if there are flows after that are not reached other than thru the fallthru
		//        clear below
		AddressIterator addrIter = locationsFixed.getAddresses(true);
		while (addrIter.hasNext()) {
			Address addr = addrIter.next();

			Instruction instruction = currentProgram.getListing().getInstructionAt(addr);
			if (instruction == null) {
				continue;
			}

			// data references could have been added because this used to be a call
			//   so get rid of data references
			Reference[] referencesFrom = instruction.getReferencesFrom();
			ReferenceManager refMgr = currentProgram.getReferenceManager();
			for (Reference reference : referencesFrom) {
				if (reference.getReferenceType().isData()) {
					refMgr.delete(reference);
				}
			}

			new SetFlowOverrideCmd(instruction.getMinAddress(), FlowOverride.BRANCH).applyTo(currentProgram);

			// make sure reference type got morphed
			referencesFrom = instruction.getReferencesFrom();
			for (Reference ref : referencesFrom) {
				if (ref.getReferenceType().isCall()) {
					refMgr.addMemoryReference(ref.getFromAddress(), ref.getToAddress(),
						RefType.UNCONDITIONAL_JUMP, ref.getSource(), ref.getOperandIndex());
					refMgr.delete(ref);
				}
			}

			createBookmark(addr, "ARM CALL to Jump fixer", "Changed Call to Jump");
		}

		// fixup functions that were affected
		aIter = funcsToFix.getAddresses(true);
		while (aIter.hasNext()) {
			Address addr = aIter.next();

			Instruction start_inst = currentProgram.getListing().getInstructionAt(addr);
			CreateFunctionCmd.fixupFunctionBody(currentProgram, start_inst, monitor);

			createBookmark(addr, " Override ARM CALL to Jump fixer", "Fixed function");
		}
	}
}
