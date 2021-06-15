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
package ghidra.app.util.pdb.pdbapplicator;

import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.*;
import ghidra.app.util.pdb.pdbapplicator.SymbolGroup.AbstractMsSymbolIterator;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Applier for {@link AbstractProcedureStartMsSymbol} and  {@link AbstractThunkMsSymbol} symbols.
 */
public class FunctionSymbolApplier extends MsSymbolApplier {

	private static final String BLOCK_INDENT = "   ";

	private AbstractProcedureMsSymbol procedureSymbol;
	private AbstractThunkMsSymbol thunkSymbol;
	private Address specifiedAddress;
	private Address address;
	private Function function = null;
	private long specifiedFrameSize = 0;
	private long currentFrameSize = 0;
	private BlockCommentsManager comments;

	private int symbolBlockNestingLevel;
	private Address currentBlockAddress;

	// might not need this, but investigating whether it will help us.  TODO remove?
	private int baseParamOffset = 0;

//	private List<RegisterRelativeSymbolApplier> stackVariableAppliers = new ArrayList<>();

	private List<MsSymbolApplier> allAppliers = new ArrayList<>();
	private RegisterChangeCalculator registerChangeCalculator;

	/**
	 * Constructor
	 * @param applicator the {@link PdbApplicator} for which we are working.
	 * @param iter the Iterator containing the symbol sequence being processed
	 * @throws CancelledException upon user cancellation
	 */
	public FunctionSymbolApplier(PdbApplicator applicator, AbstractMsSymbolIterator iter)
			throws CancelledException {
		super(applicator, iter);
		AbstractMsSymbol abstractSymbol = iter.next();
		symbolBlockNestingLevel = 0;
		comments = new BlockCommentsManager();
		currentBlockAddress = null;

		if (abstractSymbol instanceof AbstractProcedureMsSymbol) {
			procedureSymbol = (AbstractProcedureMsSymbol) abstractSymbol;
			specifiedAddress = applicator.getRawAddress(procedureSymbol);
			address = applicator.getAddress(procedureSymbol);
		}
		else if (abstractSymbol instanceof AbstractThunkMsSymbol) {
			thunkSymbol = (AbstractThunkMsSymbol) abstractSymbol;
			specifiedAddress = applicator.getRawAddress(thunkSymbol);
			address = applicator.getAddress(thunkSymbol);
		}
		else {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		manageBlockNesting(this);

		while (notDone()) {
			applicator.checkCanceled();
			MsSymbolApplier applier = applicator.getSymbolApplier(iter);
			allAppliers.add(applier);
			applier.manageBlockNesting(this);
		}
	}

	@Override
	void manageBlockNesting(MsSymbolApplier applierParam) {
		if (applierParam instanceof FunctionSymbolApplier) {
			FunctionSymbolApplier functionSymbolApplier = (FunctionSymbolApplier) applierParam;
			if (procedureSymbol != null) {
				long start = procedureSymbol.getDebugStartOffset();
				long end = procedureSymbol.getDebugEndOffset();
				Address blockAddress = address.add(start);
				long length = end - start;
				functionSymbolApplier.beginBlock(blockAddress, procedureSymbol.getName(), length);
			}
			else if (thunkSymbol != null) {
				functionSymbolApplier.beginBlock(address, thunkSymbol.getName(),
					thunkSymbol.getLength());
			}
		}
	}

	/**
	 * Returns the {@link Function} for this applier.
	 * @return the Function
	 */
	Function getFunction() {
		return function;
	}

	/**
	 * Returns the current frame size.
	 * @return the current frame size.
	 */
	long getCurrentFrameSize() {
		return currentFrameSize;
	}

	/**
	 * Returns the frame size as specified by the PDB
	 * @return the frame size.
	 */
	long getSpecifiedFrameSize() {
		return specifiedFrameSize;
	}

	/**
	 * Set the specified frame size.
	 * @param specifiedFrameSize the frame size.
	 */
	void setSpecifiedFrameSize(long specifiedFrameSize) {
		this.specifiedFrameSize = specifiedFrameSize;
		currentFrameSize = specifiedFrameSize;
	}

	/**
	 * Get the function name
	 * @return the function name
	 */
	String getName() {
		if (procedureSymbol != null) {
			return procedureSymbol.getName();
		}
		else if (thunkSymbol != null) {
			return thunkSymbol.getName();
		}
		return "";
	}

	@Override
	void applyTo(MsSymbolApplier applyToApplier) {
		// Do nothing.
	}

	@Override
	void apply() throws PdbException, CancelledException {
		boolean result = applyTo(applicator.getCancelOnlyWrappingMonitor());
		if (result == false) {
			throw new PdbException(this.getClass().getSimpleName() + ": failure at " + address +
				" applying " + getName());
		}
	}

	boolean applyTo(TaskMonitor monitor) throws PdbException, CancelledException {
		if (applicator.isInvalidAddress(address, getName())) {
			return false;
		}

		boolean functionSuccess = applyFunction(monitor);
		if (functionSuccess == false) {
			return false;
		}
		registerChangeCalculator = new RegisterChangeCalculator(procedureSymbol, function, monitor);

		baseParamOffset = VariableUtilities.getBaseStackParamOffset(function);

		for (MsSymbolApplier applier : allAppliers) {
			applier.applyTo(this);
		}

		// comments
		long addressDelta = address.subtract(specifiedAddress);
		comments.applyTo(applicator.getProgram(), addressDelta);

		// line numbers
		// TODO: not done yet
//	ApplyLineNumbers applyLineNumbers = new ApplyLineNumbers(pdbParser, xmlParser, program);
//	applyLineNumbers.applyTo(monitor, log);

		return true;
	}

	Integer getRegisterPrologChange(Register register) {
		return registerChangeCalculator.getRegChange(applicator, register);
	}

	int getBaseParamOffset() {
		return baseParamOffset;
	}

	/**
	 * Sets a local variable (address, name, type)
	 * @param address Address of the variable.
	 * @param name name of the variable.
	 * @param dataType data type of the variable.
	 */
	void setLocalVariable(Address address, String name, DataType dataType) {
		if (currentBlockAddress == null) {
			return; // silently return.
		}
		// Currently just placing a comment.
		String comment = getIndent(symbolBlockNestingLevel + 1) + "static local (stored at " +
			address + ") " + dataType.getName() + " " + name;
		comments.addPreComment(currentBlockAddress, comment);
	}

	private boolean applyFunction(TaskMonitor monitor) {
		Listing listing = applicator.getProgram().getListing();

		applicator.createSymbol(address, getName(), true);

		function = listing.getFunctionAt(address);
		if (function == null) {
			function = createFunction(monitor);
		}
		if (function != null && !function.isThunk() &&
			(function.getSignatureSource() == SourceType.DEFAULT ||
				function.getSignatureSource() == SourceType.ANALYSIS)) {
			// Set the function definition
			setFunctionDefinition(monitor);

		}
		if (function == null) {
			return false;
		}

		currentFrameSize = 0;
		return true;
	}

	private Function createFunction(TaskMonitor monitor) {

		// Does function already exist?
		Function myFunction = applicator.getProgram().getListing().getFunctionAt(address);
		if (myFunction != null) {
			// Actually not sure if we should set to 0 or calculate from the function here.
			// Need to investigate more, so at least keeping it as a separate 'else' for now.
			return myFunction;
		}

		// Disassemble
		Instruction instr = applicator.getProgram().getListing().getInstructionAt(address);
		if (instr == null) {
			DisassembleCommand cmd = new DisassembleCommand(address, null, true);
			cmd.applyTo(applicator.getProgram(), monitor);
		}

		myFunction = createFunctionCommand(monitor);

		return myFunction;
	}

	private boolean setFunctionDefinition(TaskMonitor monitor) {
		if (procedureSymbol == null) {
			// TODO: is there anything we can do with thunkSymbol?
			// long x = thunkSymbol.getParentPointer();
			return true;
		}
		// Rest presumes procedureSymbol.
		RecordNumber typeRecordNumber = procedureSymbol.getTypeRecordNumber();
		MsTypeApplier applier = applicator.getTypeApplier(typeRecordNumber);
		if (applier == null) {
			applicator.appendLogMsg("Error: Failed to resolve datatype RecordNumber " +
				typeRecordNumber + " at " + address);
			return false;
		}
		if (!(applier instanceof AbstractFunctionTypeApplier)) {
			if (!((applier instanceof PrimitiveTypeApplier) &&
				((PrimitiveTypeApplier) applier).isNoType())) {
				applicator.appendLogMsg("Error: Failed to resolve datatype RecordNumber " +
					typeRecordNumber + " at " + address);
				return false;
			}
		}

		DataType dataType = applier.getDataType();
		// Since we know the applier is an AbstractionFunctionTypeApplier, then dataType is either
		//  FunctionDefinition or no type (typedef).
		if (dataType instanceof FunctionDefinition) {
			FunctionDefinition def = (FunctionDefinition) dataType;
			ApplyFunctionSignatureCmd sigCmd =
				new ApplyFunctionSignatureCmd(address, def, SourceType.IMPORTED);
			if (!sigCmd.applyTo(applicator.getProgram(), monitor)) {
				applicator.appendLogMsg(
					"PDB Warning: Failed to apply signature to function at address " + address +
						" due to " + sigCmd.getStatusMsg() + "; dataType: " + def.getName());
				return false;
			}
		}
		return true;
	}

	private Function createFunctionCommand(TaskMonitor monitor) {
		CreateFunctionCmd funCmd = new CreateFunctionCmd(address);
		if (!funCmd.applyTo(applicator.getProgram(), monitor)) {
			applicator.appendLogMsg("Failed to apply function at address " + address.toString() +
				"; attempting to use possible existing function");
			return applicator.getProgram().getListing().getFunctionAt(address);
		}
		return funCmd.getFunction();
	}

	private boolean notDone() {
		return (symbolBlockNestingLevel > 0) && iter.hasNext();
	}

	int endBlock() {
		if (--symbolBlockNestingLevel < 0) {
			applicator.appendLogMsg(
				"Block Nesting went negative for " + getName() + " at " + address);
		}
		if (symbolBlockNestingLevel == 0) {
			//currentFunctionSymbolApplier = null;
		}
		return symbolBlockNestingLevel;
	}

	void beginBlock(Address startAddress, String name, long length) {

		int nestingLevel = beginBlock(startAddress);
		if (!applicator.getPdbApplicatorOptions().applyCodeScopeBlockComments()) {
			return;
		}
		if (applicator.isInvalidAddress(startAddress, name)) {
			return;
		}

		String indent = getIndent(nestingLevel);

		String baseComment = "level " + nestingLevel + ", length " + length;

		String preComment = indent + "PDB: Block Beg, " + baseComment;
		if (!name.isEmpty()) {
			preComment += " (" + name + ")";
		}
		comments.addPreComment(startAddress, preComment);

		String postComment = indent + "PDB: Block End, " + baseComment;
		Address endAddress = startAddress.add(((length <= 0) ? 0 : length - 1));
		comments.addPostComment(endAddress, postComment);
	}

	private int beginBlock(Address startAddress) {
		currentBlockAddress = startAddress;
		++symbolBlockNestingLevel;
		return symbolBlockNestingLevel;
	}

	private String getIndent(int indentLevel) {
		String indent = "";
		for (int i = 1; i < indentLevel; i++) {
			indent += BLOCK_INDENT;
		}
		return indent;
	}

	// Method copied from ApplyStackVariables (ghidra.app.util.bin.format.pdb package)
	//  on 20191119. TODO: Do we need something like this?
	/**
	 * Get the stack offset after it settles down.
	 * @param monitor TaskMonitor
	 * @return stack offset that stack variables will be relative to.
	 * @throws CancelledException upon user cancellation.
	 */
	private int getFrameBaseOffset(TaskMonitor monitor) throws CancelledException {

		int retAddrSize = function.getProgram().getDefaultPointerSize();

		if (retAddrSize != 8) {
			// don't do this for 32 bit.
			return -retAddrSize;  // 32 bit has a -4 byte offset
		}

		Register frameReg = function.getProgram().getCompilerSpec().getStackPointer();
		Address entryAddr = function.getEntryPoint();
		AddressSet scopeSet = new AddressSet();
		scopeSet.addRange(entryAddr, entryAddr.add(64));
		CallDepthChangeInfo valueChange =
			new CallDepthChangeInfo(function, scopeSet, frameReg, monitor);
		InstructionIterator instructions =
			function.getProgram().getListing().getInstructions(scopeSet, true);
		int max = 0;
		while (instructions.hasNext()) {
			monitor.checkCanceled();
			Instruction next = instructions.next();
			int newValue = valueChange.getDepth(next.getMinAddress());
			if (newValue < -(20 * 1024) || newValue > (20 * 1024)) {
				continue;
			}
			if (Math.abs(newValue) > Math.abs(max)) {
				max = newValue;
			}
		}
		return max;
	}

	private static class RegisterChangeCalculator {

		private Map<Register, Integer> registerChangeByRegisterName = new HashMap<>();
		private CallDepthChangeInfo callDepthChangeInfo;
		private Address debugStart;

		private RegisterChangeCalculator(AbstractProcedureMsSymbol procedureSymbol,
				Function function, TaskMonitor monitor) throws CancelledException {
			callDepthChangeInfo = createCallDepthChangInfo(procedureSymbol, function, monitor);
		}

		private CallDepthChangeInfo createCallDepthChangInfo(
				AbstractProcedureMsSymbol procedureSymbol, Function function, TaskMonitor monitor)
				throws CancelledException {
			if (procedureSymbol == null) {
				return null;
			}
			Register frameReg = function.getProgram().getCompilerSpec().getStackPointer();
			Address entryAddr = function.getEntryPoint();
			debugStart = entryAddr.add(procedureSymbol.getDebugStartOffset());
			AddressSet scopeSet = new AddressSet();
			scopeSet.addRange(entryAddr, debugStart);
			return new CallDepthChangeInfo(function, scopeSet, frameReg, monitor);
		}

		Integer getRegChange(PdbApplicator applicator, Register register) {
			if (callDepthChangeInfo == null || register == null) {
				return null;
			}
			Integer change = registerChangeByRegisterName.get(register);
			if (change != null) {
				return change;
			}
			change = callDepthChangeInfo.getRegDepth(debugStart, register);
			registerChangeByRegisterName.put(register, change);
			return change;
		}

	}
}
