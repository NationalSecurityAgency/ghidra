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
package ghidra.app.plugin.core.disassembler;

import java.util.*;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class CallFixupAnalyzer extends AbstractAnalyzer {
	private static final String DESCRIPTION =
		"Installs Call-Fixups defined by the compiler specification and fixes any functions calling Non-Returning or CallFixup Functions";
	private static final String NAME = "Call-Fixup Installer";

	private static LanguageID cachedLanguageId;
	private static CompilerSpecID cachedSpecId;
	private static Map<String, String> cachedTargetFixupMap;
	private static String lastPrimaryStatusMessage;

	public CallFixupAnalyzer() {
		this(NAME, AnalyzerType.FUNCTION_ANALYZER, true);
	}

	public CallFixupAnalyzer(String name, AnalyzerType analyzerType,
			boolean supportsOneTimeAnalysis) {
		super(name, DESCRIPTION, analyzerType);
		setPriority(AnalysisPriority.DISASSEMBLY.after().after());
		setDefaultEnablement(true);
		if (supportsOneTimeAnalysis) {
			setSupportsOneTimeAnalysis();
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);

		Map<String, String> targetFixupMap = getTargetFixupMap(program);

		// all addresses that were messed with in the program
		AddressSet codeChangeSet = new AddressSet();

		// all functions that may need fixing up, because they contain call locations that were fixed
		AddressSet funcsToFixupSet = new AddressSet();

		// Locations that should be protected from the clearing of fallout
		AddressSet protectedLocs = new AddressSet();

		// Locations where code flow was changed and needed repairing
		//  (i.e. location calling to a non-returning function)
		AddressSet repairedCallLocations = new AddressSet();

		HashSet<Function> nonFixedFuncs = new HashSet<>();
		Iterator<Function> functionIter = program.getFunctionManager().getFunctions(set, true);

		while (functionIter.hasNext()) {
			monitor.checkCanceled();

			Function function = functionIter.next();

			// if there is a callfixup for the function, set it
			//
			String fixupName = getCallFixupNameForFunction(targetFixupMap, function);
			if (fixupName != null && function.getCallFixup() == null) {
				function.setCallFixup(fixupName);
			}

			// if this function has a call fixup, even if we didn't apply it, assume something has changed!
			//
			String callFixupApplied = function.getCallFixup();
			boolean noReturn = function.hasNoReturn();

			boolean mustFix =
				noReturn || (callFixupApplied != null && !callFixupApplied.equals(""));

			if (mustFix) {
				PcodeInjectLibrary snippetLibrary =
					program.getCompilerSpec().getPcodeInjectLibrary();
				InjectPayload callFixup =
					snippetLibrary.getPayload(InjectPayload.CALLFIXUP_TYPE, callFixupApplied);
				boolean isfallthru = true;
				if (callFixup != null) {
					isfallthru = callFixup.isFallThru();
				}
				if (noReturn) {
					isfallthru = false;
				}

				if (!isfallthru) {
					// Must ensure that calls through thunks are also fixed-up 
					AddressSet functionAddresses = new AddressSet();
					functionAddresses.add(function.getEntryPoint());
					addInThunkedFunctionsToList(program, set, function, functionAddresses);

					AddressIterator iterator = functionAddresses.getAddresses(true);
					for (Address functionAddr : iterator) {
						protectedLocs.add(functionAddr);
						repairedCallLocations.add(repairLocationsForNonReturningFunction(program,
							function, functionAddr, monitor));
					}
				}
			}

			// make sure this function doesn't get added back into the fixup set!
			//   if we didn't change it. don't need any infinite looping!
			if (fixupName == null) {
				nonFixedFuncs.add(function);
			}
		}

		// Identified the locations, now fix them.
		//   Adding in any locations that have been protected from clearing for this analysis run
		protectedLocs.add(analysisMgr.getProtectedLocations());
		repairDamage(program, repairedCallLocations, protectedLocs, monitor);
		codeChangeSet.add(repairedCallLocations);

		// for the places that were fixed, add in the functions they are found in
		AddressIterator addresses = codeChangeSet.getAddresses(true);
		for (Address address : addresses) {
			monitor.checkCanceled();

			Function func = program.getFunctionManager().getFunctionContaining(address);
			if (func != null) {
				address = func.getEntryPoint();
			}

			funcsToFixupSet.addRange(address, address);
		}

		for (Function function : nonFixedFuncs) {
			// make sure functions that were'nt callfixups don't get added back into the fixup set!
			//   if we didn't change it. don't need any infinite looping!
			Address entryPoint = function.getEntryPoint();
			funcsToFixupSet.deleteRange(entryPoint, entryPoint);
			codeChangeSet.deleteRange(entryPoint, entryPoint);
		}

		// now anyone that calls this should be re-analyzed for references.
		// might want to send out code and function analysis messages
		// TODO: Don't like the way this is done.
		if (!funcsToFixupSet.isEmpty()) {
			analysisMgr.functionDefined(funcsToFixupSet);
		}
		if (!codeChangeSet.isEmpty()) {
			analysisMgr.codeDefined(codeChangeSet);
			analysisMgr.blockAdded(codeChangeSet);
		}

		return true;
	}

	private void addInThunkedFunctionsToList(Program program, AddressSetView initialSet,
			Function function, AddressSet functionAddresses) {
		Address[] thunkAddrs = function.getFunctionThunkAddresses();
		if (thunkAddrs != null) {
			for (Address addr : thunkAddrs) {
				if (!initialSet.contains(addr)) {
					// only add thunk if not contained within initial added set
					// TODO: should analysis manager do this instead so other analyzers benefit as well?
					functionAddresses.add(addr);
					// check if this function is also thunked
					Function thunkingFunc = program.getFunctionManager().getFunctionAt(addr);
					if (functionAddresses.contains(addr)) {
						continue;  // just in case, so we don't get into recursion...
					}
					if (thunkingFunc != null) {
						addInThunkedFunctionsToList(program, initialSet, thunkingFunc,
							functionAddresses);
					}
				}
			}
		}
	}

	private String getCallFixupNameForFunction(Map<String, String> targetFixupMap,
			Function function) {
		String fixupName = null;

		String funcName = function.getName();

		// get rid of any pre-pended library identification conflict string (a bit of a hack)
		if (funcName.startsWith("libID_conflict_")) {
			funcName = funcName.replace("libID_conflict_", "");
		}

		fixupName = targetFixupMap.get(funcName);
		// try with _
		if (fixupName == null) {
			fixupName = targetFixupMap.get("_" + funcName);
		}
		// try with __
		if (fixupName == null) {
			fixupName = targetFixupMap.get("__" + funcName);
		}

		return fixupName;
	}

	/**
	 * Repair a non-returning function which includes all calling points and the functions containing those calling points.
	 * 
	 * @param program functions are contained in
	 * @param func non-returning function that is causing fixes to be made
	 * @param entry point of the function that is non-returning
	 * @param monitor so we can cancel
	 * 
	 * @return location of all calling locations to the non-returning function that were fixed
	 */
	private AddressSet repairLocationsForNonReturningFunction(Program program, Function func,
			Address entry, TaskMonitor monitor) {
		AddressSet fixedCallLocations = new AddressSet();
		try {
			String name = func.getName();

			monitor.setMessage("Clearing fallthrough for: " + name);
			fixedCallLocations = setNoFallThru(program, entry);
			if (fixedCallLocations.isEmpty()) {
				return fixedCallLocations;
			}

			monitor.setMessage("Fixup function bodies for: " + name);
			fixCallingFunctionBody(program, fixedCallLocations, monitor);
		}
		catch (CancelledException e) {
			// a cancel here implies that the entire script has been cancelled
		}

		return fixedCallLocations;
	}

	private void repairDamage(Program program, AddressSet repairedCallLocations,
			AddressSet protectedLocs, TaskMonitor monitor) {
		try {
			monitor.setMessage("Clearing and repairing flows");
			clearAndRepairFlows(program, repairedCallLocations, protectedLocs, monitor);
		}
		catch (CancelledException e) {
			// a cancel here implies that the entire script has been cancelled
		}
	}

	/**
	 * Sets all locations that call the function at entry to be non-returning.
	 * 
	 * @param program function is found within
	 * @param nonReturningFunctionEntry function to be made non-returning
	 * 
	 * @return set of all locations that call the function that was set to non-returning.
	 */
	protected AddressSet setNoFallThru(Program program, Address nonReturningFunctionEntry) {
		AddressSet calledLocations = new AddressSet();

		ReferenceIterator refIter =
			program.getReferenceManager().getReferencesTo(nonReturningFunctionEntry);
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
			if (instr.getFlowOverride() != FlowOverride.CALL_RETURN && fallthruAddr != null) {
				instr.setFlowOverride(FlowOverride.CALL_RETURN);
				// some overriden flows, like conditional call, keep their fallthrough
				//   no need to fix these locations
				if (instr.getFlowType().hasFallthrough()) {
					continue;
				}
				calledLocations.add(instr.getMinAddress());
			}
		}

		return calledLocations;
	}

	/**
	 * Fix the bodies of all functions that called the non-returning function.
	 * 
	 * @param program containing the functions
	 * @param callLocations that need the bodies of the functions containing them fixed
	 * @param monitor to allow canceling
	 * 
	 * @return the set of all repaired function entry points
	 * 
	 * @throws CancelledException
	 */
	protected AddressSet fixCallingFunctionBody(Program program, AddressSet callLocations,
			TaskMonitor monitor) throws CancelledException {

		AddressSet fixedSet = new AddressSet();
		AddressSet repairedFunctions = new AddressSet();

		AddressIterator addrIter = callLocations.getAddresses(true);
		while (addrIter.hasNext()) {
			Address fromAddr = addrIter.next();

			// don't fixup already fixed locations
			if (fixedSet.contains(fromAddr)) {
				continue;
			}
			Function fixFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
			if (fixFunc == null) {
				continue;
			}

			// should always add fixed functions. any function could have an internal call to a non-returning function
			// the internal flows would have changed requiring other analysis to know about the changed body
			repairedFunctions.add(fixFunc.getEntryPoint());

			CreateFunctionCmd.fixupFunctionBody(program, fixFunc, monitor);

			fixedSet.add(fixFunc.getBody()); // new body
		}

		return repairedFunctions;
	}

	protected void clearAndRepairFlows(Program program, AddressSet repairedCallLocations,
			AddressSet protectedLocs, TaskMonitor monitor) throws CancelledException {
		//ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entry);
		long numRefs = repairedCallLocations.getNumAddresses();
		int refCnt = 0;

		lastPrimaryStatusMessage = "Repair";
		SubMonitor subMonitor = new SubMonitor(monitor);

		AddressSet clearInstSet = new AddressSet();
		AddressSet clearDataSet = new AddressSet();

		AddressIterator addrIter = repairedCallLocations.getAddresses(true);

		while (addrIter.hasNext()) {
			monitor.checkCanceled();
			monitor.setMaximum(numRefs);
			monitor.setProgress(refCnt++);
			Address fromAddr = addrIter.next();

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
			if (program.getSymbolTable().isExternalEntryPoint(fallthruAddr)) {
				continue;
			}

			// If there is a non-default function below, don't clear
			Function functionBelow = program.getFunctionManager().getFunctionAt(fallthruAddr);
			if (functionBelow != null &&
				functionBelow.getSymbol().getSource() != SourceType.DEFAULT) {
				continue;
			}

			if (!hasFlowRefInto(program, fallthruAddr)) {
				Instruction inst = program.getListing().getInstructionAt(fallthruAddr);
				if (inst != null) {
					clearInstSet.add(fallthruAddr);
				}
				else {
					clearDataSet.add(fallthruAddr);
				}
			}
		}

		program.getBookmarkManager()
				.removeBookmarks(repairedCallLocations, BookmarkType.ERROR, monitor);

		if (!clearInstSet.isEmpty()) {
			// entries including data flow referenced from instructions will be repaired
			AddressSet protect = new AddressSet(repairedCallLocations).union(protectedLocs);
			ClearFlowAndRepairCmd cmd =
				new ClearFlowAndRepairCmd(clearInstSet, protect, true, false, true);
			cmd.applyTo(program, subMonitor);
		}
		if (!clearDataSet.isEmpty()) {
			// entries that are data should not be cleared, only possible bookmarks
			ClearFlowAndRepairCmd.clearBadBookmarks(program, clearDataSet, subMonitor);
		}
	}

	private boolean hasFlowRefInto(Program program, Address addr) {
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

	private synchronized Map<String, String> getTargetFixupMap(Program program) {
		// Its possible for different compiler specs (for different processors) to share the same name
		// So we need to check both the compilerspec id and the language id
		LanguageID languageid = program.getLanguageID();
		CompilerSpec compilerSpec = program.getCompilerSpec();
		if (compilerSpec.getCompilerSpecID().equals(cachedSpecId) &&
			languageid.equals(cachedLanguageId)) {
			return cachedTargetFixupMap;
		}
		cachedLanguageId = languageid;
		cachedSpecId = compilerSpec.getCompilerSpecID();
		cachedTargetFixupMap = new HashMap<>();
		PcodeInjectLibrary snippetLibrary = compilerSpec.getPcodeInjectLibrary();
		String[] callFixupNames = snippetLibrary.getCallFixupNames();
		for (String fixupName : callFixupNames) {
			InjectPayload payload =
				snippetLibrary.getPayload(InjectPayload.CALLFIXUP_TYPE, fixupName);
			List<String> callFixupTargets = ((InjectPayloadCallfixup) payload).getTargets();
			for (String name : callFixupTargets) {
				cachedTargetFixupMap.put(name, fixupName);
			}
		}
		return cachedTargetFixupMap;
	}

	/**
	 * A monitor that let's us update the status of our overall progress monitor without
	 * altering the overall progress.
	 */
	private static class SubMonitor extends TaskMonitorAdapter {
		private final TaskMonitor parentMonitor;

		public SubMonitor(TaskMonitor parentMonitor) {
			this.parentMonitor = parentMonitor;
		}

		@Override
		public boolean isCancelled() {
			// TODO Auto-generated method stub
			return parentMonitor.isCancelled();
		}

		@Override
		public void checkCanceled() throws CancelledException {
			// TODO Auto-generated method stub
			parentMonitor.checkCanceled();
		}

		@Override
		public void cancel() {
			// TODO Auto-generated method stub
			parentMonitor.cancel();
		}

		@Override
		public void setMessage(String message) {
			parentMonitor.setMessage("<html>" + lastPrimaryStatusMessage +
				"&gt;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" + message);
		}
	}
}
