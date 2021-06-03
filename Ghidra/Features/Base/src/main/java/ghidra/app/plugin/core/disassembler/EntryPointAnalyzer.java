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
/*
 * EntryPointAnalyzer.java
 * 
 * Created on Aug 27, 2003
 */
package ghidra.app.plugin.core.disassembler;

import java.util.*;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.*;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class EntryPointAnalyzer extends AbstractAnalyzer {

	private final static String NAME = "Disassemble Entry Points";
	private static final String DESCRIPTION = "Disassembles entry points in newly added memory.";

	private final static String OPTION_NAME_RESPECT_EXECUTE_FLAG = "Respect Execute Flag";

	private static final String OPTION_DESCRIPTION_RESPECT_EXECUTE_FLAG =
		"Respect Execute flag on memory blocks when checking entry points for code.";

	private final static boolean OPTION_DEFAULT_RESPECT_EXECUTE_ENABLED = true;

	private boolean respectExecuteFlags = OPTION_DEFAULT_RESPECT_EXECUTE_ENABLED;

	private AddressSetView executeSet;

	public EntryPointAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.BLOCK_ANALYSIS);
		setDefaultEnablement(true);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		HelpLocation helpLocation =
			new HelpLocation("AutoAnalysisPlugin", "Auto_Analysis_Option_Instructions");

		options.registerOption(OPTION_NAME_RESPECT_EXECUTE_FLAG, respectExecuteFlags, helpLocation,
			OPTION_DESCRIPTION_RESPECT_EXECUTE_FLAG);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		respectExecuteFlags =
			options.getBoolean(OPTION_NAME_RESPECT_EXECUTE_FLAG, respectExecuteFlags);
	}

	@Override
	public boolean added(Program program, AddressSetView addressSet, TaskMonitor monitor,
			MessageLog log)
			throws CancelledException {

		monitor.initialize(addressSet.getNumAddresses());

		Set<Address> doNowSet = new HashSet<>();
		Set<Address> doLaterSet = new HashSet<>();

		executeSet = program.getMemory().getExecuteSet();

		if (!executeSet.isEmpty()) {
			addressSet = addressSet.intersect(executeSet);
		}

		// look at the codemap property laid down by the importer.
		//  it knows what was code, so disassemble it first
		disassembleCodeMapMarkers(program, monitor);

		// find any functions that are defined that have no code, and a single address body
		// Someone created them as a placeholder
		//   Disassemble them
		//   Remember them so the function body can be fixed later
		Set<Address> dummyFunctionSet = new HashSet<>();
		Set<Address> redoFunctionSet = new HashSet<>();
		findDummyFunctions(program, addressSet, dummyFunctionSet, redoFunctionSet);

		// disassemble dummy functions now, re-create the function bodies later
		doDisassembly(program, monitor, dummyFunctionSet);

		// add any symbols that are marked as code symbols
		addCodeSymbolsToSet(program, addressSet, monitor, doNowSet);

		// add external entry points to the doNowSet
		int externalCount = addExternalSymbolsToSet(program, addressSet, monitor, doNowSet);

		// If there is more than one external entry point, check each one for suspect functions
		if (!isSingleExternalEntryPoint(program, externalCount, doNowSet)) {
			// process the doNow set, putting suspect functions on a doLater set
			moveSuspectSymbolsToDoLaterSet(program, monitor, doNowSet, doLaterSet);
		}

		// disassemble anything on the doNowSet
		doDisassembly(program, monitor, doNowSet);

		// Anything on the doLaterSet is checked
		//    not defined as entry points, validate subroutines loosely
		checkDoLaterSet(program, monitor, doLaterSet);

		// disassemble functions on the doLater set
		processDoLaterSet(program, monitor, doLaterSet);

		// Look at the single function entry points, and see if they need to be re-created
		//    or deleted and their callers fixed
		fixDummyFunctionBodies(program, monitor, redoFunctionSet);

		return true;
	}

	/**
	 * Process the items on the do later set.  If doing block analysis, then this is the initial
	 * analysis of the program, so schedule the do later set after some analysis has occurred.
	 * 
	 * @param program - this program
	 * @param monitor - monitor
	 * @param doLaterSet - set of functions that were put off until later
	 */
	private void processDoLaterSet(Program program, TaskMonitor monitor,
			Set<Address> doLaterSet) {
		// nothing to do
		if (doLaterSet.isEmpty()) {
			return;
		}

		// 		Put off the do-later until later if doing block analysis...
		if (this.getPriority() == AnalysisPriority.BLOCK_ANALYSIS) {
			AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
			EntryPointAnalyzer entryPointAnalyzer = new EntryPointAnalyzer();
			entryPointAnalyzer.setPriority(AnalysisPriority.REFERENCE_ANALYSIS.before());
			analysisManager.scheduleOneTimeAnalysis(entryPointAnalyzer, toAddressSet(doLaterSet));
		}
		else {
			// came back in, just do it now
			doDisassembly(program, monitor, doLaterSet);
		}
	}

	/**
	 * Check for a single external entry point.
	 * 
	 * @param program - program to check
	 * @param externalCount - count of external entry points found
	 * @param doNowSet - set of functions that are to be done now
	 * 
	 * @return true if this program has only one external entry point
	 */
	private boolean isSingleExternalEntryPoint(Program program, int externalCount,
			Set<Address> doNowSet) {
		SymbolTable symbolTable = program.getSymbolTable();
		if (externalCount == 1 && doNowSet.size() == 1) {
			if (symbolTable.getPrimarySymbol(doNowSet.iterator().next()).isExternalEntryPoint()) {
				return true;
			}
		}
		return false;
	}

	private AddressSetView toAddressSet(Set<Address> doLaterSet) {
		AddressSet set = new AddressSet();
		Iterator<Address> iterator = doLaterSet.iterator();
		while (iterator.hasNext()) {
			Address address = iterator.next();
			set.add(address);
		}
		return set;
	}

	private void fixDummyFunctionBodies(Program program, TaskMonitor monitor,
			Set<Address> redoFunctionSet) throws CancelledException {
		Set<Address> recreateFunctionSet = new HashSet<>();
		for (Address entry : redoFunctionSet) {
			Function function = program.getFunctionManager().getFunctionAt(entry);
			if (function == null) {
				continue;
			}
			Instruction instr = program.getListing().getInstructionAt(entry);
			if (instr == null) {
				continue;
			}

			// go through the references, and see if there are any non-jumps to them
			ReferenceIterator referencesTo = program.getReferenceManager().getReferencesTo(entry);
			boolean foundNonJumpRef = false;
			while (referencesTo.hasNext()) {
				Reference reference = referencesTo.next();
				if (!reference.getReferenceType().isJump()) {
					foundNonJumpRef = true;
					break;
				}
			}
			if (!foundNonJumpRef) {
				// check if we have been thunked
				Address[] functionThunkAddresses = function.getFunctionThunkAddresses();
				foundNonJumpRef =
					functionThunkAddresses != null && functionThunkAddresses.length != 0;
			}

			// if found non-jump ref, or is external
			if (function.getSymbol().isExternalEntryPoint() || foundNonJumpRef) {
				recreateFunctionSet.add(entry);
			}
			else {
				referencesTo = program.getReferenceManager().getReferencesTo(entry);
				// find all functions that jumped to this one, and re-create them
				while (referencesTo.hasNext()) {
					Reference reference = referencesTo.next();
					Function func =
						program.getFunctionManager()
								.getFunctionContaining(
									reference.getFromAddress());
					if (func != null) {
						recreateFunctionSet.add(func.getEntryPoint());
					}
				}
				// does this function have a fallThru?
				Address fallFrom = instr.getFallFrom();
				if (fallFrom != null) {
					Function func = program.getFunctionManager().getFunctionContaining(fallFrom);
					if (func != null) {
						recreateFunctionSet.add(func.getEntryPoint());
					}
				}

				recreateFunctionSet.add(entry);
				// Never clear functions that are already created
				//    program.getFunctionManager().removeFunction(entry);
			}
		}

		// now re-create the function bodies for those left
		for (Address entry : recreateFunctionSet) {
			Function function = program.getFunctionManager().getFunctionAt(entry);
			CreateFunctionCmd.fixupFunctionBody(program, function, monitor);
		}
	}

	private void checkDoLaterSet(Program program, TaskMonitor monitor,
			Set<Address> doLaterSet) throws CancelledException {
		PseudoDisassembler pdis = new PseudoDisassembler(program);
		pdis.setRespectExecuteFlag(respectExecuteFlags);
		Listing listing = program.getListing();
		for (Iterator<Address> laterIter = doLaterSet.iterator(); laterIter.hasNext();) {
			Address entry = laterIter.next();

			monitor.checkCanceled();

			if (!listing.isUndefined(entry, entry)) {
				laterIter.remove();
				continue;
			}

			// relocation at this place, don't trust it
			if (program.getRelocationTable().getRelocation(entry) != null) {
				laterIter.remove();
				continue;
			}
			boolean isValid =
				pdis.isValidSubroutine(entry, true/*AllowExistingCode?*/, false/*MustTerminate?*/);
			if (!isValid) {
				laterIter.remove();
			}
		}
	}

	private void moveSuspectSymbolsToDoLaterSet(Program program, TaskMonitor monitor,
			Set<Address> doNowSet, Set<Address> doLaterSet) throws CancelledException {
		PseudoDisassembler pdis = new PseudoDisassembler(program);

		int count = 0;
		monitor.initialize(doNowSet.size());

		Listing listing = program.getListing();
		SymbolTable symbolTable = program.getSymbolTable();

		Iterator<Address> iter = doNowSet.iterator();
		while (iter.hasNext()) {
			Address entry = iter.next();

			monitor.setProgress(count++);

			monitor.checkCanceled();

			// already disassembled
			if (!listing.isUndefined(entry, entry)) {
				iter.remove();
				continue;
			}

			//  It isn't smart enough to pick up
			//    valid weird code.  Need to look at things that are marked as an entry point
			//    to see if we should disassemble...
			//  Save the bad ones to do last.
			Symbol symbol = symbolTable.getPrimarySymbol(entry);
			if (!symbol.isExternalEntryPoint()) {
				iter.remove();
				doLaterSet.add(entry);
			}
			else if (isLanguageDefinedEntry(program, entry)) {
				// check for an address
				if (isLanguageDefinedEntryPointer(program, entry)) {
					// put down an address if it is
					layDownCodePointer(program, doLaterSet, entry);
					iter.remove();
				}
			}
			else if (!isLanguageDefinedEntry(program, entry) && !pdis.isValidSubroutine(entry)) {
				doLaterSet.add(entry);
				iter.remove();
			}
		}
	}

	private void layDownCodePointer(Program program, Set<Address> doLaterSet, Address entry) {
		int defaultPointerSize = program.getDefaultPointerSize();
		try {
			Data data =
				program.getListing()
						.createData(entry,
							PointerDataType.getPointer(null, defaultPointerSize));
			Object value = data.getValue();
			if (value instanceof Address) {
				Address codeLoc = (Address) value;
				// align if necessary
				int instructionAlignment = program.getLanguage().getInstructionAlignment();
				if (codeLoc.getOffset() % instructionAlignment != 0) {
					codeLoc = codeLoc.subtract(codeLoc.getOffset() % instructionAlignment);
				}
				if (codeLoc.getOffset() != 0) {
					doLaterSet.add(codeLoc);
				}
			}
		}
		catch (CodeUnitInsertionException e) {
			// couldn't create
		}
		catch (DataTypeConflictException e) {
			// couldn't create
		}
	}

	private int addExternalSymbolsToSet(Program program, AddressSetView addressSet,
			TaskMonitor monitor, Set<Address> set) throws CancelledException {
		int externalCount = 0;

		SymbolTable symbolTable = program.getSymbolTable();
		AddressIterator aiter = program.getSymbolTable().getExternalEntryPointIterator();
		while (aiter.hasNext()) {
			externalCount++;
			monitor.checkCanceled();
			Address entryAddr = aiter.next();
			Symbol entry = symbolTable.getPrimarySymbol(entryAddr);
			// make sure to put on things that are external entry points, but not defined symbols.
			if (addressSet.contains(entryAddr) && entry.getSource() == SourceType.DEFAULT) {
				set.add(entryAddr);
			}
		}

		return externalCount;
	}

	private void addCodeSymbolsToSet(Program program, AddressSetView addressSet,
			TaskMonitor monitor, Set<Address> set) throws CancelledException {
		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator symbolIter = symbolTable.getSymbols(addressSet, SymbolType.LABEL, true);

		while (symbolIter.hasNext()) {
			monitor.checkCanceled();
			Symbol entry = symbolIter.next();
			Address entryAddr = entry.getAddress();
			if (addressSet.contains(entryAddr)) {
				set.add(entryAddr);
			}
		}
	}

	private void disassembleCodeMapMarkers(Program program, TaskMonitor monitor) {
		AddressSetPropertyMap codeProp = program.getAddressSetPropertyMap("CodeMap");
		if (codeProp != null) {
			Set<Address> codeSet = new HashSet<>();
			AddressIterator aiter = codeProp.getAddresses();
			while (aiter.hasNext()) {
				codeSet.add(aiter.next());
			}
			doDisassembly(program, monitor, codeSet);
		}
	}

	private void findDummyFunctions(Program program, AddressSetView set,
			Set<Address> dummyFunctionSet, Set<Address> redoFunctionSet) {
		FunctionIterator functions = program.getFunctionManager().getFunctions(set, true);
		while (functions.hasNext()) {
			Function function = functions.next();
			Address entryPoint = function.getEntryPoint();

			AddressSetView body = function.getBody();
			if (body == null) {
				continue;
			}
			// if there is data here, don't do
			if (program.getListing().getDefinedDataAt(entryPoint) != null) {
				continue;
			}
			// if the function has a wimpy body, put on list to re-do
			if (body.getNumAddresses() == 1) {
				redoFunctionSet.add(entryPoint);
			}
			// no code here, re-disassemble
			// if there is not undefined data at the entry point
			if (program.getListing().getInstructionAt(entryPoint) != null) {
				continue;
			}
			dummyFunctionSet.add(entryPoint);
		}
	}

	private boolean isLanguageDefinedEntry(Program program, Address addr) {
		List<AddressLabelInfo> labelList = program.getLanguage().getDefaultSymbols();
		for (AddressLabelInfo info : labelList) {
			if (addr.equals(info.getAddress())) {
				return info.isEntry();
			}
		}
		return false;
	}

	private boolean isLanguageDefinedEntryPointer(Program program, Address addr) {
		List<AddressLabelInfo> labelList = program.getLanguage().getDefaultSymbols();
		for (AddressLabelInfo info : labelList) {
			if (addr.equals(info.getAddress())) {
				ProcessorSymbolType type = info.getProcessorSymbolType();
				return type != null && type.equals(ProcessorSymbolType.CODE_PTR);
			}
		}
		return false;
	}

	private void doDisassembly(Program program, TaskMonitor monitor, Set<Address> entries) {

		if (entries.isEmpty()) {
			return;
		}

		Iterator<Address> iter = entries.iterator();
		AddressSet disSet = new AddressSet();
		while (iter.hasNext()) {
			Address entry = iter.next();
			disSet.addRange(entry, entry);
		}
		//DisassembleCommand cmd = new DisassembleCommand(disSet, null, true);
		//cmd.applyTo(program, monitor);
		// Disassemble all again
		Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
		AddressSet disassembledSet = dis.disassemble(disSet, null, true);
		AutoAnalysisManager.getAnalysisManager(program).codeDefined(disassembledSet);

		AddressSet functionEntries = new AddressSet();
		Listing listing = program.getListing();
		for (Address addr : entries) {
			if (listing.getInstructionAt(addr) != null) {
				Symbol s = program.getSymbolTable().getPrimarySymbol(addr);
				if (s != null && s.isExternalEntryPoint() &&
					listing.getFunctionContaining(addr) == null) {
					functionEntries.addRange(addr, addr);
				}
			}
		}
		if (!functionEntries.isEmpty()) {
			CreateFunctionCmd createFunctionCmd = new CreateFunctionCmd(functionEntries);
			createFunctionCmd.applyTo(program, monitor);
		}
	}

}
