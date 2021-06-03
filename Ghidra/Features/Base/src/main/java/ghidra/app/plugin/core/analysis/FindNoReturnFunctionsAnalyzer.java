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
package ghidra.app.plugin.core.analysis;

import java.util.*;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.services.*;
import ghidra.app.tablechooser.AddressableRowObject;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.lang.GhidraLanguagePropertyKeys;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Identifies functions to which Jump references exist and converts the
 * associated branching instruction flow to a CALL-RETURN
 */
public class FindNoReturnFunctionsAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Non-Returning Functions - Discovered";
	protected static final String DESCRIPTION =
		"As code is disassembled, discovers indications that functions do not return.  " +
			"When a threshold of evidence is crossed, functions are marked non-returning." +
			"The one-shot analysis action can be used if functions were created while this " +
			"analyzer was disabled or not present.";

	private final static String OPTION_FUNCTION_NONRETURN_THRESHOLD =
		"Function Non-return Threshold";

	private static final String OPTION_DESCRIPTION_FUNCTION_NONRETURN_THRESHOLD =
		"Enter the number of indications for a given function before it is considered non-returning.";

	private final static int OPTION_DEFAULT_EVIDENCE_THRESHOLD = 3;

	private int evidenceThresholdFunctions = OPTION_DEFAULT_EVIDENCE_THRESHOLD;

	private static final String OPTION_NAME_REPAIR_DAMAGE = "Repair Flow Damage";
	private static final String OPTION_DESCRIPTION_REPAIR_DAMAGE =
		"Signals to repair any flow after a call to found non-returning functions.";
	private static final boolean OPTION_DEFAULT_REPAIR_DAMAGE_ENABLED = true;

	private static final String OPTION_NAME_CREATE_BOOKMARKS = "Create Analysis Bookmarks";
	private static final String OPTION_DESCRIPTION_CREATE_BOOKMARKS =
		"Signals to create an analysis bookmark on each function marked as non-returning.";
	private static final boolean OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED = true;

	private boolean repairDamageEnabled = OPTION_DEFAULT_REPAIR_DAMAGE_ENABLED;

	private boolean createBookmarksEnabled = OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED;

	private Program program;
	private TaskMonitor monitor;

	private List<NoReturnLocations> reasonList = null;

	private Address lastGetNextFuncAddress = null;  // last addr used for getNextFunction()
	private Address nextFunction = null;            // last return nextFunction

	public FindNoReturnFunctionsAnalyzer() {
		this(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
	}

	public FindNoReturnFunctionsAnalyzer(String name, String description,
			AnalyzerType analyzerType) {
		super(name, description, analyzerType);
		setPriority(AnalysisPriority.DISASSEMBLY.after());
		setSupportsOneTimeAnalysis();
	}

	/**
	 * Called when a function has been added. Looks at address for call
	 * reference
	 * @throws CancelledException  if monitor is cancelled
	 */
	@Override
	public boolean added(Program prog, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		try {
			this.program = prog;
			this.monitor = monitor;
			this.reasonList = new ArrayList<>();
			lastGetNextFuncAddress = null;

			monitor.setMessage("NoReturn - Finding non-returning functions");

			AddressSet noReturnSet = new AddressSet();

			boolean hadOtherSuspiciousFunctions = detectNoReturn(program, noReturnSet, set);

			// run again with the new known noReturnSet
			if (hadOtherSuspiciousFunctions) {
				detectNoReturn(program, noReturnSet, set);
			}

			// mark all detected non-returning functions
			AddressIterator noreturns = noReturnSet.getAddresses(true);
			for (Address address : noreturns) {
				monitor.checkCanceled();

				setFunctionNonReturning(program, address);

				monitor.setMessage("NoReturn - Clearing fallthrough at: " + address);
				setNoFallThru(program, address);

				monitor.setMessage("NoReturn - Fixup function bodies for: " + address);
				fixCallingFunctionBody(program, address);
			}

			// repair the damage for all non-returning functions
			if (repairDamageEnabled) {
				AddressSet clearInstSet = new AddressSet();
				noreturns = noReturnSet.getAddresses(true);
				for (Address address : noreturns) {
					clearInstSet.add(findPotentialDamagedLocations(program, address));
				}
				repairDamagedLocations(monitor, clearInstSet);
			}
		}
		finally {
			this.program = null;
			this.monitor = null;
			this.reasonList = null;
		}
		return true;
	}

	/**
	 * repair any damaged locations
	 * 
	 * @param taskMonitor for cancellation
	 * @param clearInstSet locations to clear and repair
	 */
	private void repairDamagedLocations(TaskMonitor taskMonitor, AddressSet clearInstSet) {
		if (clearInstSet == null || clearInstSet.isEmpty()) {
			return;
		}
		AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);

		AddressSetView protectedSet = analysisManager.getProtectedLocations();

		// entries including data flow referenced from instructions will be repaired

		ClearFlowAndRepairCmd cmd =
			new ClearFlowAndRepairCmd(clearInstSet, protectedSet, true, false, true);
		cmd.applyTo(program, taskMonitor);
	}

	/**
	 * Set function to non-returning
	 * 
	 * @param cp program
	 * @param entry function entry to change to non-returning
	 */
	private void setFunctionNonReturning(Program cp, Address entry) {
		Function func = cp.getFunctionManager().getFunctionAt(entry);
		if (func == null) {
			CreateFunctionCmd createFunctionCmd = new CreateFunctionCmd(entry);
			createFunctionCmd.applyTo(cp);
			func = cp.getFunctionManager().getFunctionAt(entry);
			if (func == null) {
				return;
			}
		}
		// if func is null, create one at entry
		func.setNoReturn(true);
	}

	/**
	 * Set calls to the entry point to non-returning calls
	 * 
	 * @param cp current program
	 * @param entry entry point of a non-returning function
	 */
	protected void setNoFallThru(Program cp, Address entry) {
		ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entry);
		while (refIter.hasNext()) {
			Reference ref = refIter.next();
			if (!ref.getReferenceType().isCall()) {
				continue;
			}
			Address fromAddr = ref.getFromAddress();

			Instruction instr = program.getListing().getInstructionAt(fromAddr);
			if (instr == null) {
				continue;
			}
			Address fallthruAddr = instr.getFallThrough();
			if (fallthruAddr != null) {
				instr.setFlowOverride(FlowOverride.CALL_RETURN);
			}
		}
	}

	/**
	 * find locations of potential damage from calls to non-returning functions
	 * 
	 * @param prog program
	 * @param entry address of start of non-returning function
	 * 
	 * @return locations of potential instruction damage
	 */
	private AddressSet findPotentialDamagedLocations(Program prog, Address entry) {
		String name = entry.toString();

		Function func = prog.getFunctionManager().getFunctionAt(entry);
		if (func != null) {
			name = func.getName();
		}

		try {
			monitor.setMessage("NoReturn - Clearing and repairing flows for: " + name);
			return findRepairLocations(prog, entry);
		}
		catch (CancelledException e) {
			// a cancel here implies that the entire script has been cancelled
		}
		return new AddressSet();
	}

	/**
	 * Find locations that need repairing
	 * 
	 * @param cp current program
	 * @param entry non-returning function entry point
	 * @return an address set of the locations that may need repairing
	 * 
	 * @throws CancelledException if monitor is canceled
	 */
	protected AddressSet findRepairLocations(Program cp, Address entry) throws CancelledException {
		AddressSet clearInstSet = new AddressSet();
		AddressSet clearDataSet = new AddressSet();

		ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entry);
		while (refIter.hasNext()) {
			Reference ref = refIter.next();
			if (!ref.getReferenceType().isCall()) {
				continue;
			}
			Address fromAddr = ref.getFromAddress();

			Instruction instr = program.getListing().getInstructionAt(fromAddr);
			if (instr == null) {
				continue;
			}
			Address fallthruAddr = instr.getFallThrough();
			if (fallthruAddr == null) {
				try {
					fallthruAddr =
						instr.getMinAddress().addNoWrap(instr.getDefaultFallThroughOffset());
				}
				catch (AddressOverflowException e) {
					// handled below
				}
			}
			if (fallthruAddr == null) {
				continue;
			}

			// if location right below is an entry point, don't clear it
			Address checkAddr = skipNOPS(fallthruAddr);
			if (program.getSymbolTable().isExternalEntryPoint(checkAddr) ||
				program.getSymbolTable().isExternalEntryPoint(fallthruAddr)) {
				continue;
			}

			if (!hasFlowRefInto(fallthruAddr) && !hasFlowRefInto(checkAddr)) {
				Instruction inst = program.getListing().getInstructionAt(fallthruAddr);
				if (inst != null) {
					clearInstSet.add(fallthruAddr);
				}
				else {
					clearDataSet.add(fallthruAddr);
				}
			}
		}

		if (!clearDataSet.isEmpty()) {
			// entries that are data should not be cleared, only possible bookmarks
			ClearFlowAndRepairCmd.clearBadBookmarks(program, clearDataSet, monitor);
		}

		return clearInstSet;
	}

	private boolean detectNoReturn(Program cp, AddressSet noReturnSet, AddressSetView checkSet)
			throws CancelledException {

		AddressSet checkedSet = new AddressSet();

		boolean hadSuspiciousFunctions = false;

		AddressIterator refIter =
			cp.getReferenceManager().getReferenceSourceIterator(checkSet, true);
		for (Address address : refIter) {
			monitor.checkCanceled();

			// instruction may have already been checked from a non-returning call
			if (checkedSet.contains(address)) {
				continue;
			}
			checkedSet.add(address);

			// get the instruction there
			Instruction inst = cp.getListing().getInstructionAt(address);
			if (inst == null) {
				continue;
			}

			// if not a call, or has no fallthru
			if (!inst.getFlowType().isCall() || !inst.getFlowType().hasFallthrough()) {
				continue;
			}

			// check for indications the called instruction doesn't return
			if (!checkNonReturningIndicators(inst, noReturnSet)) {
				continue;
			}

			// detected a calling issue, check other instructions calling the same place
			Address[] flows = inst.getFlows();
			for (Address target : flows) {

				int count = 1;
				ReferenceIterator refsTo = cp.getReferenceManager().getReferencesTo(target);
				for (Reference reference : refsTo) {
					if (!reference.getReferenceType().isCall()) {
						continue;
					}

					Address fromAddress = reference.getFromAddress();
					if (checkedSet.contains(fromAddress)) {
						continue;
					}
					checkedSet.add(fromAddress);

					// call is already on the list
					// done here so all other calls don't get re-checked
					if (noReturnSet.contains(target)) {
						continue;
					}
					Instruction oinst = cp.getListing().getInstructionAt(fromAddress);
					if (oinst == null || !checkNonReturningIndicators(oinst, noReturnSet)) {
						continue;
					}

					// add one to count, if passes threshold, tag as non-returning
					count++;
					if (count >= evidenceThresholdFunctions) {
						noReturnSet.add(target);
						break;
					}
				}

				// was suspicious, but evidence didn't pass threshold
				if (count < evidenceThresholdFunctions) {
					// if function only calls non-returning functions
					if (targetOnlyCallsNoReturn(cp, target, noReturnSet)) {
						NoReturnLocations location =
							new NoReturnLocations(target, null, "Calls only non-returing function");
						reasonList.add(location);
						noReturnSet.add(target);
						continue;
					}
					hadSuspiciousFunctions = true;
				}
			}
		}
		return hadSuspiciousFunctions;
	}

	private boolean targetOnlyCallsNoReturn(Program cp, Address target, AddressSet noReturnSet)
			throws CancelledException {

		SimpleBlockModel model = new SimpleBlockModel(cp);

		// follow the flow of the instructions
		// if hit return, then no good
		// if hit call, check noReturn, if is stop following
		// if hit place that is called, then stop, and return no-good

		Stack<Address> todo = new Stack<>();
		todo.push(target);
		AddressSet visited = new AddressSet();
		boolean hitNoReturn = false;

		while (!todo.isEmpty()) {
			Address blockAddr = todo.pop();
			CodeBlock block = model.getCodeBlockAt(blockAddr, monitor);

			if (block == null) {
				return false;
			}
			if (visited.contains(blockAddr)) {
				continue;
			}
			visited.add(blockAddr);

			FlowType flowType = block.getFlowType();
			// terminal block and not a Call_Return that must be checked
			if (flowType.isTerminal() && !flowType.isCall()) {
				return false;
			}

			// if target has a call to it, then can't tell, but suspect...
			// add all destinations to todo
			CodeBlockReferenceIterator destinations = block.getDestinations(monitor);

			// no destinations
			if (!destinations.hasNext()) {
				return false;
			}
			while (destinations.hasNext()) {
				CodeBlockReference destRef = destinations.next();
				Address destAddr = destRef.getReference();

				FlowType destFlowType = destRef.getFlowType();

				// check call or jump to non-returning destination			
				if (destFlowType.isCall() || destFlowType.isJump()) {
					// check target
					// if non-Return, set-hit no return, and continue;
					if (noReturnSet.contains(destAddr)) {
						hitNoReturn = true;
						continue;
					}
					Function func = cp.getFunctionManager().getFunctionAt(destAddr);
					if (func != null && func.hasNoReturn()) {
						hitNoReturn = true;
						continue;
					}
					// hit terminal with returning call (could be a JUMP as well)
					if (flowType.isTerminal() && (destFlowType.isCall() || func != null)) {
						return false;
					}
				}
				if (destFlowType.isCall()) {
					continue;
				}
				// indirect flows are not part of the function
				if (destFlowType.isIndirect()) {
					continue;
				}
				todo.push(destAddr);
			}
		}

		return hitNoReturn;
	}

	/**
	 * Check for issues around a calling instruction that indicate the called function
	 * may not return.  Example issues: calls refs right after, bad instruction, data after,
	 * data ref after.
	 * 
	 * @param callInst - instruction to check
	 * @param noReturnFunctions - set of functions that are already non-returning
	 * 
	 * @return true if there are indications the called function does not return
	 * @throws CancelledException if monitor cancelled
	 */
	private boolean checkNonReturningIndicators(Instruction callInst, AddressSet noReturnFunctions)
			throws CancelledException {

		// check the address the instruction will return to
		Address fallThru = callInst.getFallThrough();

		FunctionManager funcManager = program.getFunctionManager();
		Function callingFunc = funcManager.getFunctionContaining(callInst.getMinAddress());

		Address target = null;
		Address[] flows = callInst.getFlows();
		if (flows != null && flows.length > 0) {
			target = flows[0];
		}

		// get the address of the next function after this instruction
		Address nextFuncAddr = getFunctionAfter(fallThru);

		Listing listing = program.getListing();
		while (fallThru != null) {
			/* check for a function after this call */
			if (nextFuncAddr != null && nextFuncAddr.equals(fallThru)) {
				NoReturnLocations location =
					new NoReturnLocations(target, fallThru, "Function defined after call");
				reasonList.add(location);
				return true;
			}
			/* code block model detects flow into data */
			CodeUnit cu = listing.getCodeUnitAt(fallThru);
			if (cu == null || cu instanceof Data) {
				NoReturnLocations location = new NoReturnLocations(target, callInst.getMinAddress(),
					"Falls into data after call");
				reasonList.add(location);
				return true;
			}
			Instruction instr = (Instruction) cu;

			/* check for codeblock containing a function */
			if (nextFuncAddr != null && cu.contains(nextFuncAddr)) {
				NoReturnLocations location = new NoReturnLocations(target, fallThru,
					"Function defined in instruction after call");
				reasonList.add(location);
				return true;
			}

			// check for inconsistent (data/call) references at fallthru after call
			if (hasInconsistentRefsTo(fallThru, funcManager, callingFunc, target)) {
				return true;
			}

			// check for defined data after
			Data data = listing.getDefinedDataAt(fallThru);
			if (data != null) {
				NoReturnLocations location =
					new NoReturnLocations(target, fallThru, "Data after call");
				reasonList.add(location);
				return true;
			}

			// get the next instruction in fallthru chain
			fallThru = null;
			if (instr.getFlowType().isFallthrough()) {
				fallThru = instr.getFallThrough();
			}
		}
		return false;
	}

	/**
	 * Return true if fallThru address has inconsistent (data/call) references to it.
	 * Adds the reason for non-returning reason to no return locations list.
	 * 
	 * @param addr location to check for read/write references
	 * @param funcManager function manager
	 * @param callingFunc function containing call that is being checked
	 * @param calledAddr address being called
	 * @return true if inconsistent references found in fallthru address chain after call
	 */
	private boolean hasInconsistentRefsTo(Address addr, FunctionManager funcManager,
			Function callingFunc, Address calledAddr) {
		if (program.getReferenceManager().hasReferencesTo(addr)) {
			ReferenceIterator refIterTo = program.getReferenceManager().getReferencesTo(addr);
			while (refIterTo.hasNext()) {
				Reference reference = refIterTo.next();
				RefType refType = reference.getReferenceType();
				if (refType.isRead() || refType.isWrite()) {
					// look at function the reference is coming from
					// is the function the same as the call is in
					//    This is a better indicator of non-returning
					// Random references from another function could be bad disassembly
					// or references.  This is especially true if there is only one
					// example for a calling reference.

					// TODO: if this is done before functions are created from calls
					//       then this check will do nothing
					if (callingFunc != null) {
						Function function =
							funcManager.getFunctionContaining(reference.getFromAddress());
						if (callingFunc.equals(function)) {
							NoReturnLocations location =
								new NoReturnLocations(calledAddr, reference.getToAddress(),
									"Data Reference from same function after call");
							reasonList.add(location);
							return true;
						}
					}
					else {
						// only consider references after call if the call location is not in a function
						NoReturnLocations location = new NoReturnLocations(calledAddr,
							reference.getToAddress(), "Data Reference after call");
						reasonList.add(location);
						return true;
					}
				}
				if (refType.isCall()) {
					NoReturnLocations location = new NoReturnLocations(calledAddr,
						reference.getToAddress(), "Call Reference after call");
					reasonList.add(location);
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Get the next defined function after the current address.
	 * 
	 * Save the returned function along with the address
	 * The nextFunction will be valid for any getNextFunction call for
	 * addresses from lastGetNextFuncAddress to nextFunction,
	 * which avoids an expensive funcMgr.getNextFunction() call
	 * 
	 * @param addr address to find the next defined function after
	 * @return return the next function if found, or null otherwise
	 */
	private Address getFunctionAfter(Address addr) {
		if (addr == null) {
			return null;
		}
		if (lastGetNextFuncAddress != null && addr.compareTo(lastGetNextFuncAddress) >= 0) {
			if (nextFunction == null || addr.compareTo(nextFunction) <= 0) {
				return nextFunction;
			}
		}
		FunctionIterator functions = program.getFunctionManager().getFunctions(addr, true);
		nextFunction = null;
		lastGetNextFuncAddress = addr;
		if (functions.hasNext()) {
			nextFunction = functions.next().getEntryPoint();
		}
		return nextFunction;
	}

	protected void fixCallingFunctionBody(Program cp, Address entry) throws CancelledException {
		if (createBookmarksEnabled) {
			cp.getBookmarkManager().setBookmark(entry, BookmarkType.ANALYSIS,
				"Non-Returning Function", "Non-Returning Function Found");
		}
		AddressSet fixedSet = new AddressSet();

		ReferenceIterator refIter = cp.getReferenceManager().getReferencesTo(entry);
		while (refIter.hasNext()) {
			Reference ref = refIter.next();
			if (!ref.getReferenceType().isCall()) {
				continue;
			}
			Address fromAddr = ref.getFromAddress();

			// don't fixup already fixed locations
			if (fixedSet.contains(fromAddr)) {
				continue;
			}
			Function fixFunc = cp.getFunctionManager().getFunctionContaining(fromAddr);
			if (fixFunc == null) {
				continue;
			}
			AddressSetView oldBody = fixFunc.getBody();

			AddressSetView newBody = CreateFunctionCmd.getFunctionBody(cp, fixFunc.getEntryPoint());
			if (oldBody.equals(newBody)) {
				fixedSet.add(newBody);
				continue;
			}
			CreateFunctionCmd.fixupFunctionBody(cp, fixFunc, monitor);
			Function newFunc = cp.getFunctionManager().getFunctionContaining(fromAddr);

			if (newFunc != null) {
				newBody = newFunc.getBody();
				fixedSet.add(newBody);
			}
		}
	}

	private boolean hasFlowRefInto(Address addr) {
		if (addr == null) {
			return false;
		}

		// check the flows into the next instruction
		ReferenceIterator refs = program.getReferenceManager().getReferencesTo(addr);
		while (refs.hasNext()) {
			Reference ref = refs.next();
			RefType refType = ref.getReferenceType();
			if (refType.isFlow()) {
				return true;
			}
		}
		return false;
	}

	private Address skipNOPS(Address addr) {
		// skip over NOPS
		int count = 0;
		while (addr != null && count < 16) {
			Instruction instructionAt = program.getListing().getInstructionAt(addr);
			if (instructionAt == null) {
				return addr;
			}

			// any flow breaks
			if (!instructionAt.getFlowType().isFallthrough()) {
				return addr;
			}

			// instruction has PCODE, might not be a NOP
			PcodeOp[] pcode = instructionAt.getPcode();
			if (pcode != null && pcode.length != 0) {
				// must do an operation, or assign to non-unique
				for (PcodeOp pCode : pcode) {
					int opcode = pCode.getOpcode();
					switch (opcode) {
						case PcodeOp.LOAD:
						case PcodeOp.STORE:
						case PcodeOp.CALLOTHER:
						case PcodeOp.SEGMENTOP:
							return addr;
					}
					Varnode output = pCode.getOutput();
					if (output != null && !output.isUnique()) {
						return addr;
					}
				}
			}

			addr = instructionAt.getFallThrough();
			// this shouldn't happen, to have no fallthru, you should have flow, but could be override
			if (addr == null) {
				return instructionAt.getMinAddress();
			}
			count++;
		}
		return addr;
	}

	@Override
	public boolean getDefaultEnablement(Program prog) {
		Language language = prog.getLanguage();

		boolean noReturnEnabled = language.getPropertyAsBoolean(
			GhidraLanguagePropertyKeys.ENABLE_NO_RETURN_ANALYSIS, true);

		return noReturnEnabled;
	}

	@Override
	public void registerOptions(Options options, Program prog) {
		HelpLocation helpLocation =
			new HelpLocation("AutoAnalysisPlugin", "Auto_Analysis_Option_Instructions");

		options.registerOption(OPTION_FUNCTION_NONRETURN_THRESHOLD,
			OPTION_DEFAULT_EVIDENCE_THRESHOLD, helpLocation,
			OPTION_DESCRIPTION_FUNCTION_NONRETURN_THRESHOLD);

		options.registerOption(OPTION_NAME_REPAIR_DAMAGE, repairDamageEnabled, null,
			OPTION_DESCRIPTION_REPAIR_DAMAGE);

		options.registerOption(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled, null,
			OPTION_DESCRIPTION_CREATE_BOOKMARKS);

	}

	@Override
	public void optionsChanged(Options options, Program prog) {

		evidenceThresholdFunctions =
			options.getInt(OPTION_FUNCTION_NONRETURN_THRESHOLD, OPTION_DEFAULT_EVIDENCE_THRESHOLD);

		repairDamageEnabled = options.getBoolean(OPTION_NAME_REPAIR_DAMAGE, repairDamageEnabled);

		createBookmarksEnabled =
			options.getBoolean(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled);

	}

	class NoReturnLocations implements AddressableRowObject {
		private Address addr;
		private Address whyAddr;
		private String explanation;

		NoReturnLocations(Address suspectNoRetAddr, Address whyAddr, String explanation) {
			this.addr = suspectNoRetAddr;
			this.whyAddr = whyAddr;
			this.explanation = explanation;

			// log.appendMsg(toString());
		}

		@Override
		public Address getAddress() {
			return getNoReturnAddr();
		}

		public Address getNoReturnAddr() {
			return addr;
		}

		public Address getWhyAddr() {
			return whyAddr;
		}

		public String getExplanation() {
			return explanation;
		}

		@Override
		public String toString() {
			return "NoReturn At:" + getAddress() + "  because: " + getExplanation() +
				(whyAddr != null ? " at " + whyAddr : "");
		}
	}
}
