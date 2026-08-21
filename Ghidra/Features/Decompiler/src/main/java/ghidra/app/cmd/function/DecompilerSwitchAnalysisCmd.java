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
package ghidra.app.cmd.function;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.docking.settings.SettingsImpl;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.pcode.JumpTable.LoadTable;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.UndefinedFunction;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class DecompilerSwitchAnalysisCmd extends BackgroundCommand<Program> {
	private static final int DEFAULT_CASE_VALUE = 0xbad1abe1;

	private Program program;
	private DecompileResults decompilerResults;

	protected DecompInterface decompiler;
	private boolean useArraysForSwitchTables = false;

	public DecompilerSwitchAnalysisCmd(DecompileResults decompileResults) {
		this.decompilerResults = decompileResults;
	}

	@Override
	public boolean applyTo(Program p, TaskMonitor monitor) {
		program = p;

		if (monitor.isCancelled()) {
			return false;
		}

		analyzeFunction(monitor);
		return true;
	}

	private void analyzeFunction(TaskMonitor monitor) {

		if (!decompilerResults.decompileCompleted()) {
			return;
		}

		try {
			monitor.checkCancelled();

			Function f = decompilerResults.getFunction();
			HighFunction hfunction = decompilerResults.getHighFunction();
			
			String errMsg = getStatusMsg();
			if (hfunction == null) {
				String msg = (errMsg != null && errMsg.length() != 0) ? (": " + errMsg) : "";
				Msg.debug(this, "  Failed to decompile function: " + f.getName() + msg);
			}
			
			processBranchIND(f, hfunction, monitor);
		}
		catch (Exception e) {
			if (!monitor.isCancelled()) {
				String errMsg = e.getMessage();
				if (errMsg == null) {
					errMsg = "Error decompiling function: " + e;
				}
				setStatusMsg(errMsg);
			}
		}
	}

	private void processBranchIND(Function f, HighFunction hfunction, TaskMonitor monitor)
			throws CancelledException {
		JumpTable[] tables = hfunction.getJumpTables();
		for (JumpTable table : tables) {
			Address switchAddr = table.getSwitchAddress();

			Instruction instr = program.getListing().getInstructionAt(switchAddr);
			if (instr == null) {
				continue;
			}

			Function containingFunction =
				program.getFunctionManager().getFunctionContaining(switchAddr);
			if (containingFunction != null && !containingFunction.equals(f)) {
				continue; // skip switch owned by a different defined function
			}

			// references already there, ignore this table
			if (hasAllReferences(monitor, table, instr, containingFunction)) {
				continue;
			}

			FlowType flowType = instr.getFlowType();
			if (flowType.isCall()) {
				flowType = RefType.COMPUTED_JUMP;
			}
			else {
				// clear out the old references
				program.getReferenceManager().removeAllReferencesFrom(instr.getMinAddress());
			}

			// label the table and cases
			labelSwitch(table, monitor);

			// disassemble the table
			disassembleTable(monitor, table, instr, flowType);

			// fixup the function body
			fixupFunction(f, monitor, instr);
		}
	}

	/*
	 * Fix the functions body with any newly reached code from the switch recovery
	 */
	private void fixupFunction(Function f, TaskMonitor monitor, Instruction instr)
			throws CancelledException {
		Function fixupFunc = f;
		
		// Make sure this case isn't the result of an undefined function,
		// that somehow one of the cases found a real function.
		if (fixupFunc instanceof UndefinedFunction) {
			Function realFunc =
				program.getFunctionManager().getFunctionContaining(instr.getMinAddress());
			if (realFunc != null) {
				fixupFunc = realFunc;
			}
		}
		Instruction funcStartInstr =
			program.getListing().getInstructionAt(fixupFunc.getEntryPoint());
		CreateFunctionCmd.fixupFunctionBody(program, funcStartInstr, monitor);
	}

	/*
	 * Disassemble all code reached from the table.
	 * Also adds the case flow references to the switching instruction.
	 */
	private void disassembleTable(TaskMonitor monitor, JumpTable table,
			Instruction instr, FlowType flowType) throws CancelledException {
		
		Address switchAddr = table.getSwitchAddress();
		
		// pull out the current context so we can flow anything that needs to flow
		ProgramContext programContext = program.getProgramContext();
		Register baseContextRegister = programContext.getBaseContextRegister();
		RegisterValue switchContext = null;
		if (baseContextRegister != null) {
			// Use disassembler context based upon context register value at switch address (i.e., computed jump)
			// Only use flowing context bits
			switchContext = programContext.getRegisterValue(baseContextRegister, switchAddr);
			switchContext = programContext.getFlowValue(switchContext);
		}

		Listing listing = program.getListing();
		Address[] cases = table.getCases();
		Integer[] caseValues = table.getLabelValues();
		AddressSet disSetList = new AddressSet();

		for (int caseIndex = 0; caseIndex < cases.length; caseIndex++) {
			Address caseStart = cases[caseIndex];
			monitor.checkCancelled();
			
			if (!isDefaultCase(caseValues, caseIndex)) {
				// only non-default cases should be added to the switching instruction
				instr.addMnemonicReference(caseStart, flowType, SourceType.ANALYSIS);
			}

			// if conflict skip case
			if (listing.getUndefinedDataAt(caseStart) == null) {
				continue;
			}
			// already done
			if (disSetList.contains(caseStart)) {
				continue;
			}
			try {
				setSwitchTargetContext(programContext, caseStart, switchContext);
			}
			catch (ContextChangeException e) {
				// This can occur when two or more threads are working on the same function
				continue;
			}
			disSetList.add(caseStart);
		}

		// do all cases at one time
		if (!disSetList.isEmpty()) {
			DisassembleCommand cmd = new DisassembleCommand(disSetList, null, true);
			cmd.applyTo(program);
		}
	}

	/*
	 * Check if this case index is a default case.
	 * 
	 * In general, each case target address should have an associated caseValue.
	 * A case is default if it is first case to not have a case value, or has a magic case value.
	 * It is possible that there could be more than one case without a value.  The code shouldn't
	 * blow up if this is the case.
	 * 
	 * TODO: Should this check if the default case already has a reference to it
	 *       from a conditional jump?
	 */
	private boolean isDefaultCase(Integer[] caseValues, int caseIndex) {
		return (caseIndex == caseValues.length) ||
				(caseIndex < caseValues.length && caseValues[caseIndex] == DEFAULT_CASE_VALUE);
	}

	/*
	 * Check if the switching instruction has all switch references already.
	 * Extra check for default case target as part of the table, when it shouldn't be.
	 */
	public boolean hasAllReferences(TaskMonitor monitor, JumpTable table, Instruction instr,
			Function containingFunction) throws CancelledException {
		AddressSetView containingBody =
			containingFunction != null ? containingFunction.getBody() : null;

		Reference[] referencesFrom = instr.getReferencesFrom();
		Address[] tableDest = table.getCases();
		Integer[] caseValues = table.getLabelValues();

		// check that all cases are already a reference on the instruction, except default
		for (int caseIndex = 0; caseIndex < tableDest.length; caseIndex++) {
			monitor.checkCancelled();
			
			// a case is default if it is first case to not have a value, or has a magic case value
			boolean isDefaultCase = isDefaultCase(caseValues, caseIndex);
			
			if (containingBody != null && !containingBody.contains(tableDest[caseIndex])) {
				// switch case missing from owner function's body
				return false;
			}

			boolean foundit = false;
			for (Reference element : referencesFrom) {
				if (element.getToAddress().equals(tableDest[caseIndex])) {
					foundit = true;
					break;
				}
			}
			if (isDefaultCase) {
				// default case should not be on switching instruction
				if (foundit) {
					return false;
				}
			}
			else if (!foundit) {
				return false;
			}
		}
		
		return true;
	}

	/*
	 * Set the context that should flow to the target so that target instruction will disassemble correctly
	 */
	private void setSwitchTargetContext(ProgramContext programContext, Address targetStart, RegisterValue switchContext) throws ContextChangeException {
		if (switchContext == null) {
			return;
		}
		
		// Combine flowed switch context with context register value at case address
		RegisterValue curContext =
			programContext.getNonDefaultValue(switchContext.getRegister(), targetStart);
		if (curContext != null) {
			switchContext = curContext.combineValues(switchContext);
		}
		
		if (switchContext == null || !switchContext.hasAnyValue()) {
			return;
		}

		// only store if different than what is already there, which could be a default value
		program.getProgramContext().setRegisterValue(targetStart, targetStart, switchContext);
	}

	/*
	 * Label switch table, cases, default with labels in namespace of the switch
	 */
	private void labelSwitch(JumpTable table, TaskMonitor monitor) throws CancelledException {
		AddLabelCmd tableNameLabel =
			new AddLabelCmd(table.getSwitchAddress(), "switchD", SourceType.ANALYSIS);

		// check if the table is already labeled
		Symbol syms[] = program.getSymbolTable().getSymbols(table.getSwitchAddress());
		for (Symbol sym : syms) {
			if (sym.getName(false).startsWith(tableNameLabel.getLabelName())) {
				return;
			}
		}

		// put switch table cases into a new switch namespace
		Namespace space = null;
		String switchName = "switchD_" + table.getSwitchAddress();
		try {
			space = program.getSymbolTable().createNameSpace(null, switchName, SourceType.ANALYSIS);
		}
		catch (DuplicateNameException e) {
			space = program.getSymbolTable().getNamespace(switchName, null);
		}
		catch (InvalidInputException e) {
			// just go with default space
		}

		// label the switch
		tableNameLabel.setNamespace(space);
		tableNameLabel.applyTo(program);

		Address[] switchCases = table.getCases();
		Integer[] caseValues = table.getLabelValues();
		Symbol[] caseSymbols = new Symbol[caseValues.length];
		SymbolTable symTable = program.getSymbolTable();

		for (int caseIndex = 0; caseIndex < switchCases.length; caseIndex++) {
			monitor.checkCancelled();
			
			// if there are more switchCases than switch values, just use the caseIndex
			int caseValue = (caseIndex < caseValues.length) ? caseValues[caseIndex] : caseIndex;

			boolean isDefaultCase = isDefaultCase(caseValues, caseIndex);
			
			String caseName = "caseD_" + Integer.toHexString(caseValue);
			if (isDefaultCase) {
				caseName = "default";
			}
			AddLabelCmd lcmd =
				new AddLabelCmd(switchCases[caseIndex], caseName, space, SourceType.ANALYSIS);

			Symbol oldSym = symTable.getPrimarySymbol(lcmd.getLabelAddr());
			if (oldSym != null && oldSym.getSource() == SourceType.ANALYSIS &&
				oldSym.getName().startsWith("Addr")) {
				// cleanup AddressTableAnalyzer label
				oldSym.delete();
			}
			if (lcmd.applyTo(program) && caseIndex < caseSymbols.length) {
				caseSymbols[caseIndex] = symTable.getSymbol(caseName, switchCases[caseIndex], space);
			}
		}

		JumpTable.LoadTable loadtable[] = table.getLoadTables();
		for (LoadTable element : loadtable) {
			labelLoadTable(element, switchCases, caseSymbols, space, monitor);
		}
	}

	private Address[] getPointerTable(JumpTable.LoadTable loadtable, Address[] switchCases) {

		int size = loadtable.getSize();
		int num = loadtable.getNum();

		if (size > 8) {
			return null;
		}

		AddressSpace addrspace = switchCases[0].getAddressSpace();
		Address[] addresses = new Address[num];

		DataType entrydt =
			AbstractIntegerDataType.getUnsignedDataType(size, program.getDataTypeManager());

		Address addr = loadtable.getAddress();
		DumbMemBufferImpl buf = new DumbMemBufferImpl(program.getMemory(), addr);
		for (int i = 0; i < num; i++) {
			int tableOffset = size * i;
			Address nextAddr = addr.add(tableOffset);
			buf.setPosition(nextAddr);

			Scalar scalar = (Scalar) entrydt.getValue(buf, SettingsImpl.NO_SETTINGS, 0);
			long unsignedOffset = scalar.getUnsignedValue() * addrspace.getAddressableUnitSize();
			long signedOffset = scalar.getSignedValue() * addrspace.getAddressableUnitSize();

			boolean found = false;
			for (Address caddr : switchCases) {
				long offset = caddr.getOffset();
				if (offset == unsignedOffset || offset == signedOffset) {
					found = true;
					addresses[i] = caddr;
					break;
				}
			}
			if (!found) {
				return null;
			}
		}
		return addresses;
	}

	/*
	 * put labels on the switch table used to compute the target addresses of the switch.
	 */
	private void labelLoadTable(JumpTable.LoadTable loadtable, Address[] switchCases,
			Symbol[] caseSymbols, Namespace space, TaskMonitor monitor) throws CancelledException {

		DataTypeManager dtmanager = program.getDataTypeManager();

		Address[] pointers = getPointerTable(loadtable, switchCases);
		boolean usingPointers = false;

		Address tableAddr = loadtable.getAddress();
		int size = loadtable.getSize();
		int num = loadtable.getNum();

		DataType entrydt = AbstractIntegerDataType.getUnsignedDataType(size, dtmanager);
		if (pointers != null) {
			int defaultPtrSize = program.getDefaultPointerSize();
			if (defaultPtrSize == size &&
				defaultPtrSize == switchCases[0].getAddressSpace().getPointerSize()) {
				entrydt = PointerDataType.getPointer(null, dtmanager);
				usingPointers = true;
			}
		}
		DataType fulldt = null;

		if (num > 1 && useArraysForSwitchTables) {
			fulldt = new ArrayDataType(entrydt, num, size);
			num = 1;
		}
		else {
			fulldt = entrydt;
		}

		// Create load table data
		for (int i = 0; i < num; i++) {
			monitor.checkCancelled();
			Address addr = tableAddr.addWrap(i * size);
			Data defData = program.getListing().getDefinedDataAt(addr);
			if (defData != null) {
				if (!Undefined.isUndefined(defData.getDataType())) {
					continue;
				}
			}
			CreateDataCmd cmd = new CreateDataCmd(addr, true, fulldt);
			cmd.applyTo(program);
			markDataAsConstant(addr);
		}

		// Create pointer table references when unable to apply pointer datatype
		if (pointers != null && !usingPointers) {
			ReferenceManager refMgr = program.getReferenceManager();
			for (int i = 0; i < num; i++) {
				monitor.checkCancelled();
				int tableOffset = size * i;
				Address addr = tableAddr.add(tableOffset);
				refMgr.addMemoryReference(addr, switchCases[i], RefType.DATA, SourceType.ANALYSIS,
					0);
			}
		}

		String dataName = "switchdataD_" + loadtable.getAddress();
		// check if the table is already labeled
		Symbol syms[] = program.getSymbolTable().getSymbols(tableAddr);
		for (Symbol sym : syms) {
			if (sym.getName(false).startsWith(dataName)) {
				return;
			}
		}
		AddLabelCmd dataNameLabel = new AddLabelCmd(tableAddr, dataName, SourceType.ANALYSIS);
		dataNameLabel.setNamespace(space);
		dataNameLabel.applyTo(program);

	}

	public final void markDataAsConstant(Address addr) {
		Data data = program.getListing().getDataAt(addr);
		if (data == null) {
			return;
		}
		SettingsDefinition[] settings = data.getDataType().getSettingsDefinitions();
		for (SettingsDefinition definitions : settings) {
			if (definitions instanceof MutabilitySettingsDefinition) {
				MutabilitySettingsDefinition setting = (MutabilitySettingsDefinition) definitions;
				setting.setChoice(data, MutabilitySettingsDefinition.CONSTANT);
			}
		}
	}
}
