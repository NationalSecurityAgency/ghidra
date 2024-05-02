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

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Applier for {@link AbstractProcedureStartMsSymbol} and  {@link AbstractThunkMsSymbol} symbols.
 */
public class FunctionSymbolApplier extends AbstractBlockContextApplier
		implements BlockNestingSymbolApplier, DisassembleableAddressSymbolApplier {

	private Function function = null;

	// Do not trust any of these variables... this is work in progress (possibly getting
	//  torn up), but non-functioning code in other classes or this class still depend on these
	private long specifiedFrameSize_x = 0;
	private long currentFrameSize_x = 0;

	// might not need this, but investigating whether it will help us.  TODO remove?
	private int baseParamOffset = 0;

	private RegisterChangeCalculator registerChangeCalculator;

	private AbstractProcedureMsSymbol symbol;

	/**
	 * Constructor
	 * @param applicator the {@link DefaultPdbApplicator} for which we are working.
	 * @param symbol the symbol for this applier
	 */
	public FunctionSymbolApplier(DefaultPdbApplicator applicator,
			AbstractProcedureMsSymbol symbol) {
		super(applicator);
		this.symbol = symbol;
	}

	//==============================================================================================
	@Override
	public void apply(MsSymbolIterator iter) throws PdbException, CancelledException {
		// Pealing the symbol off again, as the iterator is coming in fresh, and we need the symbol
		getValidatedSymbol(iter, true);
		processSymbol(iter);
	}

	@Override
	public Address getAddressForDisassembly() {
		return applicator.getAddress(symbol);
	}

	private void processSymbol(MsSymbolIterator iter)
			throws CancelledException, PdbException {

		Address address = applicator.getAddress(symbol);
		String name = symbol.getName();

		// Regardless of ability to apply this symbol, we need to progress through symbols to the
		//  matching "end" symbol before we return
		if (!processEndSymbol(symbol.getEndPointer(), iter)) {
			applicator.appendLogMsg("PDB: Failed to process function at address " + address);
			return;
		}

		if (applicator.isInvalidAddress(address, name)) {
			applicator.appendLogMsg("PDB: Failed to process function at address: " + address);
			return;
		}

		function = applicator.getExistingOrCreateOneByteFunction(address);
		if (function == null) {
			return;
		}

		boolean succeededSetFunctionSignature = setFunctionDefinition(function, address);

		// If signature was set, then override existing primary mangled symbol with
		// the global symbol that provided this signature so that Demangler does not overwrite
		// the richer data type we get with global symbols.
		applicator.createSymbol(address, name, succeededSetFunctionSignature);
	}

	/**
	 * returns true only if we set a function signature
	 * @return true if function signature was set
	 * @throws PdbException upon processing error
	 * @throws CancelledException upon user cancellation
	 */
	private boolean setFunctionDefinition(Function function, Address address)
			throws CancelledException, PdbException {

		RecordNumber typeRecordNumber = symbol.getTypeRecordNumber();
		if (typeRecordNumber == RecordNumber.NO_TYPE) {
			return false; // This will happen for thunks (we set to NO_TYPE specifically)
		}
		// Remaining are non-thunks

		if (function.getSignatureSource().isHigherPriorityThan(SourceType.ANALYSIS)) {
			// return if IMPORTED or USER_DEFINED
			return false;
		}

		// Since the thunk detection algorithms are overly aggressive and make mistakes, we
		//  are specifically clearing the value to override these false positives
		function.setThunkedFunction(null);

		function.setNoReturn(isNonReturning());

		AbstractMsType fType = applicator.getTypeRecord(typeRecordNumber);
		MsTypeApplier applier = applicator.getTypeApplier(fType);
		if (!(applier instanceof AbstractFunctionTypeApplier)) {
			applicator.appendLogMsg("Error: Failed to resolve datatype RecordNumber " +
				typeRecordNumber + " at " + address);
			return false;
		}

		DataType dataType = applicator.getCompletedDataType(typeRecordNumber);
		// Since we know the applier is an AbstractionFunctionTypeApplier, then dataType is either
		//  FunctionDefinition or no type (typedef).
		if (!(dataType instanceof FunctionDefinition)) {
			return false;
		}
		FunctionDefinition def =
			(FunctionDefinition) dataType.copy(applicator.getDataTypeManager());
		try {
			// Must use copy of function definition with preserved function name.
			// While not ideal, this prevents applying an incorrect function name
			// with an IMPORTED source type
			def.setName(function.getName());
		}
		catch (InvalidNameException | DuplicateNameException e) {
			throw new RuntimeException("unexpected exception", e);
		}
		ApplyFunctionSignatureCmd sigCmd =
			new ApplyFunctionSignatureCmd(address, def, SourceType.IMPORTED);
		TaskMonitor monitor = applicator.getCancelOnlyWrappingMonitor();
		if (!sigCmd.applyTo(applicator.getProgram(), monitor)) {
			applicator.appendLogMsg(
				"PDB Warning: Failed to apply signature to function at address " + address +
					" due to " + sigCmd.getStatusMsg() + "; dataType: " + def.getName());
			return false;
		}
		return true;
	}

	//==============================================================================================
	@Override
	public void deferredApply(MsSymbolIterator iter) throws PdbException, CancelledException {
		// Pealing the symbol off again, as the iterator is coming in fresh, and we need the symbol
		getValidatedSymbol(iter, true);

		String name = symbol.getName();
		Address address = applicator.getAddress(symbol);

		function = applicator.getExistingFunction(address);
		if (function == null) {
			// Skip all interim symbols records
			if (!processEndSymbol(symbol.getEndPointer(), iter)) {
				applicator.appendLogMsg("PDB: Failed to process function at address " + address);
			}
			return;
		}

		long start = getStartOffset();
		long end = getEndOffset();
		Address blockAddress = address.add(start);
		long length = end - start;

		deferredProcessing(iter, name, address, blockAddress, length);
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
		return currentFrameSize_x;
	}

	/**
	 * Returns the frame size as specified by the PDB
	 * @return the frame size.
	 */
	long getSpecifiedFrameSize() {
		return specifiedFrameSize_x;
	}

	/**
	 * Set the specified frame size.
	 * @param specifiedFrameSize the frame size.
	 */
	@Override
	void setSpecifiedFrameSize(long specifiedFrameSize) {
		this.specifiedFrameSize_x = specifiedFrameSize;
		currentFrameSize_x = specifiedFrameSize;
	}

	/**
	 * Get the function name
	 * @return the function name
	 */
	String getName() {
		return symbol.getName();
	}

	//==============================================================================================
	//==============================================================================================
	Integer getRegisterPrologChange(Register register) {
		return registerChangeCalculator.getRegChange(applicator, register);
	}

	int getBaseParamOffset() {
		return baseParamOffset;
	}

	/**
	 * Sets a local variable (address, name, type)
	 * @param varAddress Address of the variable.
	 * @param varName varName of the variable.
	 * @param dataType data type of the variable.
	 */
	void setLocalVariable(Address varAddress, String varName, DataType dataType) {
		if (varAddress == null) {
			return; // silently return.
		}
		if (varName.isBlank()) {
			return; // silently return.
		}

		String plateAddition =
			"PDB: static local for function (" + applicator.getAddress(symbol) + "): " + getName();
		// TODO: 20220210... consider adding function name as namespace to varName
		applicator.createSymbol(varAddress, varName, false, plateAddition);
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
			monitor.checkCancelled();
			Instruction next = instructions.next();
			int newValue = valueChange.getDepth(next.getMinAddress());
			// 20240131 review had comment about the these special values.  TODO: When this
			//  code gets reworked, if these numbers stay, then document why "these" values, etc.
			if (newValue < -(20 * 1024) || newValue > (20 * 1024)) {
				continue;
			}
			if (Math.abs(newValue) > Math.abs(max)) {
				max = newValue;
			}
		}
		return max;
	}

	//==============================================================================================

	@Override
	long getStartOffset() {
		return symbol.getDebugStartOffset();
	}

	@Override
	long getEndOffset() {
		return symbol.getDebugEndOffset();
	}

	private boolean isNonReturning() {
		if (symbol instanceof AbstractProcedureStartMsSymbol procMs) {
			return procMs.getFlags().doesNotReturn();
		}
		else if (symbol instanceof AbstractProcedureStartIa64MsSymbol procIa64) {
			return procIa64.getFlags().doesNotReturn();
		}
		else if (symbol instanceof AbstractProcedureStartMipsMsSymbol procMips) {
			return false; // we do not have ProcedureFlags to check
		}
		else if (symbol instanceof AbstractThunkMsSymbol procThunk) {
			// Value is not used when thunk; is controlled by thunked function;
			//  Thus, the return value is a fake value
			return false;
		}
		throw new AssertException(
			"PDB: getNonReturning: Invalid symbol type: " + symbol.getClass().getSimpleName());
	}

	private AbstractProcedureMsSymbol getValidatedSymbol(MsSymbolIterator iter, boolean iterate) {
		AbstractMsSymbol abstractSymbol = iterate ? iter.next() : iter.peek();
		if (!(abstractSymbol instanceof AbstractProcedureMsSymbol procSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		return procSymbol;
	}

}
