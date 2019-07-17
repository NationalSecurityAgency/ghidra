/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.cmd.analysis;

import ghidra.app.cmd.disassemble.SetFlowOverrideCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.List;

/**
 * Identifies functions to which Jump references exist and converts 
 * the associated branching instruction flow to a CALL-RETURN
 */
public class SharedReturnAnalysisCmd extends BackgroundCommand {

	private AddressSetView set;
	private boolean assumeContiguousFunctions = false;
	private boolean considerConditionalBranches = false;

	/**
	 * Constructor
	 * @param set set of addresses over which destination functions will be
	 * examined for Jump reference to those functions.
	 * @param assumeContiguousFunctions if true it will be assumed that any unconditional
	 * jump over another function will trigger a call-return override and the creation of
	 * @param considerConditionalBranches if true conditional jumps can also be considered for jumping
	 * to another function as a shared return.
	 * a function at the destination.
	 */
	public SharedReturnAnalysisCmd(AddressSetView set, boolean assumeContiguousFunctions,
			boolean considerConditionalBranches) {
		super("Shared Return Analysis", false, true, false);
		this.set = set;
		this.assumeContiguousFunctions = assumeContiguousFunctions;
		this.considerConditionalBranches = considerConditionalBranches;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {

		Program program = (Program) obj;

		try {

			// Check destination functions within set
			SymbolTable symbolTable = program.getSymbolTable();
			SymbolIterator fnSymbols = symbolTable.getSymbols(set, SymbolType.FUNCTION, true);
			while (fnSymbols.hasNext()) {
				monitor.checkCanceled();
				Symbol s = fnSymbols.next();
				Address entry = s.getAddress();

				processFunctionJumpReferences(program, entry, monitor);
			}

			if (assumeContiguousFunctions) {
				// assume if checkAllJumpReferences then set is much more than new function starts

				AddressSet jumpScanSet = new AddressSet();

				fnSymbols = symbolTable.getSymbols(set, SymbolType.FUNCTION, true);
				while (fnSymbols.hasNext()) {
					monitor.checkCanceled();
					Symbol s = fnSymbols.next();
					checkAboveFunction(s, jumpScanSet);
					checkBelowFunction(s, jumpScanSet);
				}

				// Used for caching forward/backward function lookups as we
				// move forward through jump references
				Address functionAfterSrc = null;
				Address functionBeforeSrc = null;

				ReferenceManager refMgr = program.getReferenceManager();
				AddressIterator refSrcIter = refMgr.getReferenceSourceIterator(jumpScanSet, true);
				while (refSrcIter.hasNext()) {
					monitor.checkCanceled();
					Address srcAddr = refSrcIter.next();
					RefType flow = null;
					Address destAddr = null;
					for (Reference ref : refMgr.getReferencesFrom(srcAddr)) {
						RefType refType = ref.getReferenceType();
						if (refType.isFlow()) {
							if (flow != null) {
								// ignore points with multiple flows
								break;
							}
							flow = refType;
							destAddr = ref.getToAddress();
						}
					}
					if (destAddr == null || flow == null || !flow.isJump() ||
						!flow.isUnConditional()) {
						continue;
					}
					if (srcAddr.getAddressSpace() != destAddr.getAddressSpace()) {
						continue; // can't handle flows between different spaces/overlays
					}

					// Reset cached functions if we transition to a different space/overlay
					if (functionAfterSrc != null &&
						functionAfterSrc.getAddressSpace() != srcAddr.getAddressSpace()) {
						functionAfterSrc = null;
					}
					if (functionBeforeSrc != null &&
						functionBeforeSrc.getAddressSpace() != srcAddr.getAddressSpace()) {
						functionBeforeSrc = null;
					}

					if (srcAddr.compareTo(destAddr) < 0) {
						// forward jump
						if (functionAfterSrc == Address.NO_ADDRESS) {
							continue; // no function after srcAddr
						}
						if (functionAfterSrc == null || functionAfterSrc.compareTo(srcAddr) <= 0) {
							Function nextFunction = getFunctionAfter(program, srcAddr);
							if (nextFunction != null) {
								functionAfterSrc = nextFunction.getEntryPoint();
							}
							else {
								functionAfterSrc = Address.NO_ADDRESS;
								continue; // no function after srcAddr
							}
						}
						if (destAddr.compareTo(functionAfterSrc) >= 0) {
							createFunction(program, destAddr, monitor);
						}
					}
					else {

						// prime lastFunctionAfterSrc if not previously set
						if (functionAfterSrc == null) {
							Function nextFunction = getFunctionAfter(program, srcAddr);
							if (nextFunction != null) {
								functionAfterSrc = nextFunction.getEntryPoint();
							}
							else {
								functionAfterSrc = Address.NO_ADDRESS;
							}
						}

						// backward jump
						if (functionBeforeSrc == Address.NO_ADDRESS) {
							if (functionAfterSrc == Address.NO_ADDRESS) {
								continue; // no functions exist - rare
							}
							if (srcAddr.compareTo(functionAfterSrc) < 0) {
								continue; // we have not passed next function - no function before
							}
							functionBeforeSrc = null; // must re-query - lastFunctionAfterSrc is also invalid
							Function nextFunction = getFunctionAfter(program, srcAddr);
							if (nextFunction != null) {
								functionAfterSrc = nextFunction.getEntryPoint();
							}
							else {
								functionAfterSrc = Address.NO_ADDRESS;
							}
						}

						// if we have not passed lastFunctionAfter then no change to lastFunctionBefore
						if (functionBeforeSrc != null &&
							(functionAfterSrc == Address.NO_ADDRESS || srcAddr.compareTo(functionAfterSrc) < 0)) {
							// we have not passed lastFunctionAfterSrc - no change to lastFunctionBeforeSrc
						}
						else {
							Function prevFunction = getFunctionBefore(program, srcAddr);
							if (prevFunction != null) {
								functionBeforeSrc = prevFunction.getEntryPoint();
							}
							else {
								functionBeforeSrc = Address.NO_ADDRESS;
								continue; // no function before srcAddr
							}
						}

						if (destAddr.compareTo(functionBeforeSrc) < 0) {
							createFunction(program, destAddr, monitor);
						}

					}
				}
			}

		}
		catch (CancelledException e) {
			// ignore
		}

		return true;
	}

	private Function getFunctionBefore(Program program, Address addr) {
		Listing listing = program.getListing();
		FunctionIterator prevFunctionIter =
			listing.getFunctions(getRangeBefore(program, addr), false);
		if (prevFunctionIter.hasNext()) {
			return prevFunctionIter.next();
		}
		return null;
	}

	private AddressSetView getRangeBefore(Program program, Address addr) {
		AddressSpace space = addr.getAddressSpace();
		Address min = space.getMinAddress();
		if (addr.equals(min)) {
			return new AddressSet();
		}
		try {
			return new AddressSet(min, addr.subtractNoWrap(1));
		}
		catch (AddressOverflowException e) {
			throw new AssertException(e);
		}
	}

	private Function getFunctionAfter(Program program, Address addr) {
		Listing listing = program.getListing();
		FunctionIterator nextFunctionIter =
			listing.getFunctions(getRangeAfter(program, addr), true);
		if (nextFunctionIter.hasNext()) {
			return nextFunctionIter.next();
		}
		return null;
	}

	private AddressSetView getRangeAfter(Program program, Address addr) {
		AddressSpace space = addr.getAddressSpace();
		Address max = space.getMaxAddress();
		if (addr.equals(max)) {
			return new AddressSet();
		}
		try {
			return new AddressSet(addr.addNoWrap(1), max);
		}
		catch (AddressOverflowException e) {
			throw new AssertException(e);
		}
	}

	private void createFunction(Program program, Address entry, TaskMonitor monitor)
			throws CancelledException {
		if (program.getFunctionManager().getFunctionAt(entry) != null) {
			processFunctionJumpReferences(program, entry, monitor);
		}
		else {
			AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);
			analysisMgr.createFunction(entry, false);
		}
	}

	private void checkAboveFunction(Symbol functionSymbol, AddressSet jumpScanSet) {

		Program program = functionSymbol.getProgram();
		Address fnAddr = functionSymbol.getAddress();
		Function prevFunction = getFunctionBefore(program, fnAddr);
		if (prevFunction != null) {
			// Must scan everything from previous function down to functionSymbol
			jumpScanSet.addRange(prevFunction.getEntryPoint(), fnAddr);
			return;
		}

		// Must scan everything above function
		jumpScanSet.addRange(fnAddr.getAddressSpace().getMinAddress(), fnAddr);
	}

	private void checkBelowFunction(Symbol functionSymbol, AddressSet jumpScanSet) {

		Function function = (Function) functionSymbol.getObject();
		AddressSetView body = function.getBody();
		if (body.getNumAddressRanges() > 1) {
			jumpScanSet.add(body);
		}

		Program program = functionSymbol.getProgram();
		Address fnAddr = functionSymbol.getAddress();
		Function nextFunction = getFunctionAfter(program, fnAddr);
		if (nextFunction != null) {
			// Must scan everything from this function down to next functionSymbol
			// If function body has single range - omit from scan
			jumpScanSet.addRange(fnAddr, nextFunction.getEntryPoint().subtract(1));
			if (body.getNumAddressRanges() <= 1) {
				jumpScanSet.delete(body);
			}
			return;
		}

		// Must scan everything below function
		// If function body has single range - omit from scan
		jumpScanSet.addRange(fnAddr, fnAddr.getAddressSpace().getMaxAddress());
		if (body.getNumAddressRanges() <= 1) {
			jumpScanSet.delete(body);
		}

	}

	private void checkAllJumpReferences(Program program, TaskMonitor monitor)
			throws CancelledException {

		SymbolTable symbolTable = program.getSymbolTable();

		InstructionIterator instructionIter = program.getListing().getInstructions(set, true);
		while (instructionIter.hasNext()) {
			monitor.checkCanceled();
			Instruction instr = instructionIter.next();
			FlowType ft = instr.getFlowType();
			if (!ft.isJump()) {
				continue;
			}
			Reference ref = getSingleFlowReferenceFrom(instr);
			if (ref == null) {
				continue;
			}
			// if there is a function at this address, this is a thunk
			//    Handle differently
			if (program.getFunctionManager().getFunctionAt(instr.getMinAddress()) != null) {
				continue;
			}
			Symbol s = symbolTable.getPrimarySymbol(ref.getToAddress());
			if (s != null && s.getSymbolType() == SymbolType.FUNCTION) {
				if (instr.getFlowOverride() != FlowOverride.NONE) {
					continue;
				}
				SetFlowOverrideCmd cmd =
					new SetFlowOverrideCmd(instr.getMinAddress(), FlowOverride.CALL_RETURN);
				cmd.applyTo(program);
			}
		}
	}

	private void processFunctionJumpReferences(Program program, Address entry, TaskMonitor monitor)
			throws CancelledException {

		// since reference fixup will occur when flow override is done,
		// avoid concurrent modification during reference iterator use
		// by building list of jump references
		List<Reference> fnRefList = getJumpRefsToFunction(program, entry, monitor);
		if (fnRefList == null) {
			return;
		}

		for (Reference ref : fnRefList) {
			monitor.checkCanceled();
			Instruction instr = program.getListing().getInstructionAt(ref.getFromAddress());
			if (instr == null) {
				continue;
			}
			Reference checkRef = getSingleFlowReferenceFrom(instr);
			if (checkRef == null) {
				continue;
			}
			// if there is a function at this address, this is a thunk
			//    Handle differently
			if (program.getFunctionManager().getFunctionAt(instr.getMinAddress()) != null) {
				continue;
			}
			if (checkRef.getToAddress().equals(ref.getToAddress())) {
				if (instr.getFlowOverride() != FlowOverride.NONE) {
					continue;
				}
				SetFlowOverrideCmd cmd =
					new SetFlowOverrideCmd(instr.getMinAddress(), FlowOverride.CALL_RETURN);
				cmd.applyTo(program);
			}
		}
	}

	private List<Reference> getJumpRefsToFunction(Program program, Address entry,
			TaskMonitor monitor) throws CancelledException {
		List<Reference> fnRefList = null;
		ReferenceIterator referencesTo = program.getReferenceManager().getReferencesTo(entry);
		while (referencesTo.hasNext()) {
			monitor.checkCanceled();
			Reference ref = referencesTo.next();
			if (!ref.getReferenceType().isJump()) {
				continue;
			}
			if (ref.getReferenceType().isConditional() && !considerConditionalBranches) {
				// any conditional jumps don't count, only pure jumps are considered.
				//   
				continue;
			}
			if (fnRefList == null) {
				fnRefList = new ArrayList<Reference>();
			}
			fnRefList.add(ref);
		}
		return fnRefList;
	}

	private Reference getSingleFlowReferenceFrom(Instruction instr) {
		Reference ref = null;
		int flowCnt = 0;
		for (Reference refFrom : instr.getReferencesFrom()) {
			if (!refFrom.isMemoryReference() || !refFrom.getReferenceType().isFlow()) {
				continue;
			}
			if (++flowCnt > 1) {
				return null; // only change if single flow
			}
			ref = refFrom;
		}
		return ref;
	}
}
