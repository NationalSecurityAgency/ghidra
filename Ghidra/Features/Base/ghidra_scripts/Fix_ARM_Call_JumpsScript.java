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
// Finds all calls that should actually be Jumps and re-tags them as a Jump.
//   Some compilers for the ARM use a typical (bl <x>)call instruction as a form of long jump.
//   The bl instruction is a branch and link, usually associated with a call.
//   The ARM language module has the ability to override the call instruction with a CALLOVERRIDE context.
//
//   Using the Multiple entry subroutine model,
//   look at each function in a program to decide if it has calls
//   to itself.  If it does, change those calls to a jump.
//
//   There is one degenerate case, where somewhere in a function it jumps to the first instruction in a subroutine
//   while other locations really do call the location.
//
//   This script assumes good flow, that switch stmts are good.
//
//@category ARM

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.disassemble.SetFlowOverrideCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class Fix_ARM_Call_JumpsScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		ReferenceManager refMgr = currentProgram.getReferenceManager();

		// get rid of all previously overridden instructions branch/call instructions
		AddressSet clearSet = new AddressSet();
		InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
		for (Instruction instruction : instructions) {
			if (instruction.getFlowOverride().equals(FlowOverride.BRANCH)) {
				clearSet.add(instruction.getMinAddress());
			}
		}
		AddressIterator addresses = clearSet.getAddresses(true);
		this.setCurrentHighlight(clearSet);
		for (Address address : addresses) {
			// don't get rid of ARM/Thumb context
			currentProgram.getListing().clearCodeUnits(address, address, false, monitor);
		}
		// re-disassemble, but don't fix things
		DisassembleCommand cmd = new DisassembleCommand(clearSet, null, true);
		cmd.enableCodeAnalysis(false);
		cmd.applyTo(currentProgram, monitor);

		// The multi-entry model gets all subs that may have multiple call entry points in them.
		//
		MultEntSubModel model = new MultEntSubModel(currentProgram);

		CodeBlockIterator subIter = model.getCodeBlocks(monitor);

		AddressSet funcsToClear = new AddressSet();
		AddressSet funcsToFix = new AddressSet();

		AddressSet locationsFixed = new AddressSet();

		// find all incestuous functions.
		while (subIter.hasNext()) {
			CodeBlock multiEntryBlock = subIter.next();

			// branchSet will contain those addresses that need to be changed to a jump in this block
			AddressSet branchSet = new AddressSet();

			boolean isBad = false;
			SimpleBlockModel basicBlockModel = new SimpleBlockModel(currentProgram);
			CodeBlockIterator bbIter =
				basicBlockModel.getCodeBlocksContaining(multiEntryBlock, monitor);

			while (bbIter.hasNext()) {
				CodeBlock basicBlock = bbIter.next();

				CodeBlockReferenceIterator bbDestRefIter = basicBlock.getDestinations(monitor);
				while (bbDestRefIter.hasNext()) {
					CodeBlockReference bbRef = bbDestRefIter.next();

					Address targetAddr = bbRef.getDestinationAddress();
					if (isBadReference(multiEntryBlock, bbRef, targetAddr)) {
						// don't wack external entry points
						Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(targetAddr);
						if (sym != null && sym.isExternalEntryPoint()) {
							continue;
						}

						Instruction instr =
							currentProgram.getListing().getInstructionContaining(
								basicBlock.getMaxAddress());
						// something strange with this one, let it go
						if (hasStrangeReferences(instr)) {
							break;
						}

						// check that the called place is not legitimately reached by a call that is not part of this block
						// if this is that last flow in the block
						ReferenceIterator refsAt =
							currentProgram.getReferenceManager().getReferencesTo(targetAddr);
						boolean hitGoodCall = false;
						while (refsAt.hasNext()) {
							Reference reference = refsAt.next();
							if (reference.getReferenceType().isCall() &&
								!multiEntryBlock.contains(reference.getFromAddress())) {
								hitGoodCall = true;
								break;
							}
						}
						if (hitGoodCall) {
							continue;
						}

						// must override at call location
						branchSet.addRange(instr.getMinAddress(), instr.getMinAddress());

						// don't clear the function at the top of this subroutine block
						// functions that are jumped to if they are really the target of a call
						if (!bbRef.getDestinationAddress().equals(multiEntryBlock.getMinAddress())) {
							// must clear function at destination
							funcsToClear.addRange(targetAddr, targetAddr);
						}
						isBad = true;
					}
				}
			}

			if (!isBad) {
				continue;
			}

			// this is one bad one
			funcsToFix.addRange(multiEntryBlock.getFirstStartAddress(),
				multiEntryBlock.getFirstStartAddress());
			goTo(multiEntryBlock.getFirstStartAddress());
			createSelection(funcsToFix);

			locationsFixed.add(branchSet);
			createHighlight(locationsFixed);
		}

		// get rid of the bad functions
		AddressIterator aIter = funcsToClear.getAddresses(true);
		while (aIter.hasNext()) {
			Address addr = aIter.next();
			currentProgram.getFunctionManager().removeFunction(addr);

			createBookmark(addr, "ARM CALL to Jump fixer", "Removed Bogus function");
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
			for (Reference reference : referencesFrom) {
				if (reference.getReferenceType().isData()) {
					refMgr.delete(reference);
					// println("Deleted ref at " + instruction.getMinAddress());
				}
			}

			new SetFlowOverrideCmd(instruction.getMinAddress(), FlowOverride.BRANCH).applyTo(currentProgram);

			// data references could have been added because this used to be a call
			//   so get rid of data references
			referencesFrom = instruction.getReferencesFrom();
			for (Reference reference : referencesFrom) {
				if (reference.getReferenceType().isData()) {
					refMgr.delete(reference);
					// println("Deleted ref at " + instruction.getMinAddress());
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
			// TOOD: now that body is fixed up,
			//    may need to coalesce the body of the function.
			//    anything inside the body may need to be considered.
			createBookmark(addr, "ARM CALL to Jump fixer", "Fixed function");
		}
	}

	private boolean isBadReference(CodeBlock multiEntryBlock, CodeBlockReference bbRef,
			Address targetAddr) {
		if (bbRef.getFlowType().isCall()) {
			return multiEntryBlock.contains(targetAddr);
		}

		if (bbRef.getFlowType().hasFallthrough()) {
			Function functionAt = currentProgram.getFunctionManager().getFunctionAt(targetAddr);
			if (functionAt != null) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if this instruction has strange references we shouldn't mess with
	 */
	private boolean hasStrangeReferences(Instruction instr) {
		if (instr.getFlowOverride() != FlowOverride.NONE) {
			return true;
		}

		// should only have a call, and maybe some data references from param refs.
		boolean hadCall = false;
		Reference[] referencesFrom = instr.getReferencesFrom();
		for (Reference reference : referencesFrom) {
			RefType referenceType = reference.getReferenceType();
			if (hadCall == false && referenceType.isCall()) {
				hadCall = true;
				continue;
			}
			if (referenceType.isData()) {
				continue;
			}
			return true;
		}

		boolean hasIndirect = false;
		for (int i = 0; i < referencesFrom.length; i++) {
			if (referencesFrom[i].getReferenceType().isIndirect()) {
				hasIndirect = true;
			}
		}
		if (hasIndirect) {
			return true;
		}
		// There must be another way to get to any instruction below this.
		Instruction nextInstr = instr.getNext();
		if (nextInstr == null) {
			return false;
		}
		if (!instr.getFallThrough().equals(nextInstr.getMinAddress())) {
			return false;
		}
		ReferenceIterator referenceIteratorTo = nextInstr.getReferenceIteratorTo();
		while (referenceIteratorTo.hasNext()) {
			Reference reference = referenceIteratorTo.next();
			// found a reference other than this one
			if (reference.getFromAddress() != instr.getMinAddress()) {
				return false;
			}
		}
		return true;
	}
}
