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

import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.app.util.bin.format.pdb2.pdbreader.MsSymbolIterator;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractManagedProcedureMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.bin.format.pe.cli.tables.CliAbstractTableRow;
import ghidra.app.util.bin.format.pe.cli.tables.CliTableMethodDef.CliMethodDefRow;
import ghidra.app.util.bin.format.pe.cli.tables.CliTableMethodImpl.CliMethodImplRow;
import ghidra.app.util.bin.format.pe.cli.tables.CliTableMethodSemantics.CliMethodSemanticsRow;
import ghidra.app.util.bin.format.pe.cli.tables.CliTableMethodSpec.CliMethodSpecRow;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

// NOTE: This class is currently just a stub applier that does not do much except try to
// protect the context of all of the other symbols around it.  Mainly, it was not being
// processed in the past, but now does partial processing, in that it tries to maintain the
// integrity of the block nesting that we monitor.
// TODO: This class was started as a copy of FunctionSymbolApplier.  As this is worked on, we
// need to determine if it can be a proper child of the class or if FunctionSymbolApplier
// should be adapted to handle both.  Much of the code below, even if not yet used, can serve
// as a foundation for determining how we should process "Managed" procedures.
/**
 * Applier for {@link AbstractManagedProcedureMsSymbol} symbols.
 */
public class ManagedProcedureSymbolApplier extends AbstractBlockContextApplier
		implements BlockNestingSymbolApplier, DisassembleableAddressSymbolApplier {

	private int symbolBlockNestingLevel;
	private Address currentBlockAddress;

	// might not need this, but investigating whether it will help us.  TODO remove?
	private int baseParamOffset = 0;

	private AbstractManagedProcedureMsSymbol symbol;

	// TODO: We are having difficulty figuring out how to process these... actually not getting
	//  correct addresses in some situations.  This flag allows us to bypass this symbol and
	//  its nested symbols.
	private boolean developerStillHavingProblemProcessingThese = true;

	/**
	 * Constructor
	 * @param applicator the {@link DefaultPdbApplicator} for which we are working.
	 * @param symbol the symbol for this applier
	 */
	public ManagedProcedureSymbolApplier(DefaultPdbApplicator applicator,
			AbstractManagedProcedureMsSymbol symbol) {
		super(applicator);
		this.symbol = symbol;
	}

	@Override
	public void apply(MsSymbolIterator iter) throws PdbException, CancelledException {
		getValidatedSymbol(iter, true);
		processSymbol(iter);
	}

	@Override
	public Address getAddressForDisassembly() {
		return applicator.getAddress(symbol);
	}

	// TODO.  Investigate more.  This is not working for at least one CLI dll in that we are
	// not getting correct addresses.  There is no omap and the one section is unnamed.
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

		// Eventually will remove this when we know how to process
		if (developerStillHavingProblemProcessingThese) {
			applicator.getPdbApplicatorMetrics().witnessCannotApplySymbolType(symbol);
			return;
		}

		if (applicator.isInvalidAddress(address, name)) {
			applicator.appendLogMsg("PDB: Failed to process function at address: " + address);
			return;
		}

		Function function = applicator.getExistingOrCreateOneByteFunction(address);
		if (function == null) {
			return;
		}

		boolean succeededSetFunctionSignature = setFunctionDefinition(function, address, symbol);

		// If signature was set, then override existing primary mangled symbol with
		// the global symbol that provided this signature so that Demangler does not overwrite
		// the richer data type we get with global symbols.
		applicator.createSymbol(address, name, succeededSetFunctionSignature);
	}

	@Override
	public void deferredApply(MsSymbolIterator iter)
			throws PdbException, CancelledException {
		// Pealing the symbol off again, as the iterator is coming in fresh, and we need the symbol
		getValidatedSymbol(iter, true);

		// Eventually will remove this when we know how to process
		if (developerStillHavingProblemProcessingThese) {
			processEndSymbol(symbol.getEndPointer(), iter);
			return;
		}

		String name = symbol.getName();
		Address address = applicator.getAddress(symbol);

		long start = getStartOffset();
		long end = getEndOffset();
		Address blockAddress = address.add(start);
		long length = end - start;

		// Not sure if following procedure from parent class can be used or if should be
		// specialized below
		deferredProcessing(iter, name, address, blockAddress, length);

	}

//	private void deferredProcessing(MsSymbolIterator iter)
//			throws CancelledException, PdbException {
//
//		long currentFrameSize = 0;
//
////		symbolBlockNestingLevel = 0;
////		BlockCommentsManager comments = new BlockCommentsManager();
////		currentBlockAddress = null;
//
//		// TODO: Remove the witness call once we effectively process this class of symbols
//		//  See that the applyTo() method is much unimplemented.
//		applicator.getPdbApplicatorMetrics().witnessCannotApplySymbolType(symbol);
//
//		Address specifiedAddress = applicator.getRawAddress(symbol);
//		Address address = applicator.getAddress(symbol);
//		boolean isNonReturning = symbol.getFlags().doesNotReturn();
//
//		initContext();
//		applyTo(this, context, iter);
//
////		TaskMonitor monitor = applicator.getCancelOnlyWrappingMonitor();
////		RegisterChangeCalculator registerChangeCalculator =
////			new RegisterChangeCalculator(symbol, function, monitor);
////
////		// TODO: need to decide how/where these get passed around... either we pass the function
////		//  around or pass things in the blockNestingContext or other
////		int baseParamOffset = VariableUtilities.getBaseStackParamOffset(function_x);
////		long currentFrameSize = 0;
//
//		while (notDone(context, iter)) {
//			applicator.checkCancelled();
//			AbstractMsSymbol subSymbol = iter.peek();
//
//			// TODO: msSymbol, subSymbol, comments, currentFrameSize, baseParmOffset
//
//			MsSymbolApplier applier = applicator.getSymbolApplier(subSymbol, iter);
////			if (applier instanceof BlockNestingSymbolApplier nestingApplier) {
////				//nestingApplier.manageBlockNesting(iter, blockNestingContext);
////				nestingApplier.applyTo(this, context, iter);
////			}
//			if (applier instanceof NestableSymbolApplier nestingApplier) {
//				nestingApplier.applyTo(this, iter);
//			}
//			else {
//				applicator.getPdbApplicatorMetrics().witnessNonNestableSymbolType(subSymbol);
//				iter.next();
//			}
//		}
//
//		// comments
//		//TODO: deal with specifiedAddress vs. address... do we still want to do any of this
////		long addressDelta = address_x.subtract(specifiedAddress_x);
////		blockNestingContext.getComments().applyTo(applicator.getProgram(), addressDelta);
//		context.getComments().applyTo(applicator.getProgram(), 0);
//
////		// line numbers
////		// TODO: not done yet
//////	ApplyLineNumbers applyLineNumbers = new ApplyLineNumbers(pdbParser, xmlParser, program);
//////	applyLineNumbers.applyTo(monitor, log);
//
//	}

//	boolean applyTo(TaskMonitor monitor) throws PdbException, CancelledException {
//		if (applicator.isInvalidAddress(address, getName())) {
//			return false;
//		}
//
//		// TODO: We do not know, yet, how/where to apply this.  Need to wait for other .NET
//		// work to get done for loading.  Have commented-out code below, but have added some
//		// functionality (laying down symbol).  This file was somewhat copied from
//		// FunctionSymbolApplier.
//		// TODO: Also see the TODO in the constructor regarding the call to witness.
//		for (MsSymbolApplier applier : allAppliers) {
//			applier.applyTo(this);
//		}
//
//		boolean functionSuccess = applyFunction(procedureSymbol);
//		if (functionSuccess == false) {
//			return false;
//		}
////		registerChangeCalculator = new RegisterChangeCalculator(procedureSymbol, function, monitor);
////
////		baseParamOffset = VariableUtilities.getBaseStackParamOffset(function);
////
////		for (MsSymbolApplier applier : allAppliers) {
////			applier.applyTo(this);
////		}
////
////		// comments
////		long addressDelta = address.subtract(specifiedAddress);
////		comments.applyTo(applicator.getProgram(), addressDelta);
//
//		// line numbers
//		// TODO: not done yet
////	ApplyLineNumbers applyLineNumbers = new ApplyLineNumbers(pdbParser, xmlParser, program);
////	applyLineNumbers.applyTo(monitor, log);
//
//		return true;
//	}

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
		String comment =
			context.getIndent(symbolBlockNestingLevel + 1) + "static local (stored at " +
				address + ") " + dataType.getName() + " " + name;
		context.getComments().addPreComment(currentBlockAddress, comment);
	}

//	private boolean applyFunction(AbstractManagedProcedureMsSymbol procedureSymbol) {
//
//		Address address = applicator.getAddress(procedureSymbol);
//		String name = procedureSymbol.getName();
//
//		applicator.createSymbol(address, name, true);
//
//		Function function = applicator.getExistingOrCreateOneByteFunction(address);
//		if (function == null) {
//			return false;
//		}
////		applicator.scheduleDeferredFunctionWork(this);
//		applicator.scheduleDisassembly(address);
//
//		boolean isNonReturning = procedureSymbol.getFlags().doesNotReturn();
//
//		if (!function.isThunk() &&
//			function.getSignatureSource().isLowerPriorityThan(SourceType.IMPORTED)) {
//			setFunctionDefinition(applicator.getCancelOnlyWrappingMonitor());
//			function.setNoReturn(isNonReturning);
//		}
//		//currentFrameSize = 0;
//		return true;
//	}
//
	/**
	 * returns true only if we set a function signature
	 * @return true if function signature was set
	 * @throws PdbException upon processing error
	 * @throws CancelledException upon user cancellation
	 */
	private boolean setFunctionDefinition(Function function, Address address,
			AbstractManagedProcedureMsSymbol symbol) throws CancelledException, PdbException {

		if (function.getSignatureSource().isHigherPriorityThan(SourceType.ANALYSIS)) {
			// return if IMPORTED or USER_DEFINED
			return false;
		}

		// Since the thunk detection algorithms are overly aggressive and make mistakes, we
		//  are specifically clearing the value to override these false positives
		function.setThunkedFunction(null);

		function.setNoReturn(isNonReturning());

		// Rest presumes procedureSymbol.
		long token = symbol.getToken();
		// TODO: once GP-328 is merged, use static methods to get table and row.
		// CliIndexUtils.getTableIdUnencoded(token) and .getRowIdUnencoded(token).
		int table = (int) (token >> 24) & 0xff;
		int row = (int) (token & 0xffffff);

		//This is all under investigation at this time.
		CliAbstractTableRow tableRow;
		try {
			tableRow = applicator.getCliTableRow(table, row);
			if (tableRow instanceof CliMethodDefRow) {
				CliMethodDefRow def = (CliMethodDefRow) tableRow;
				// investigate what to do next
			}
			if (tableRow instanceof CliMethodImplRow) {
				CliMethodImplRow def = (CliMethodImplRow) tableRow;
				// investigate what to do next
			}
			if (tableRow instanceof CliMethodSemanticsRow) {
				CliMethodSemanticsRow def = (CliMethodSemanticsRow) tableRow;
				// investigate what to do next
			}
			if (tableRow instanceof CliMethodSpecRow) {
				CliMethodSpecRow def = (CliMethodSpecRow) tableRow;
				// investigate what to do next
			}
			else {
				// investigate what to do next
			}
		}
		catch (PdbException e) {
			// do nothing for now... just investigating
			return false;
		}

		// TODO: something :)

//
//		RecordNumber typeRecordNumber = procedureSymbol.getTypeRecordNumber();
//		MsTypeApplier applier = applicator.getTypeApplier(typeRecordNumber);
//
//		if (applier == null) {
//			applicator.appendLogMsg("Error: Failed to resolve datatype RecordNumber " +
//				typeRecordNumber + " at " + address);
//			return false;
//		}
//		if (!(applier instanceof AbstractFunctionTypeApplier)) {
//			if (!((applier instanceof PrimitiveTypeApplier) &&
//				((PrimitiveTypeApplier) applier).isNoType())) {
//				applicator.appendLogMsg("Error: Failed to resolve datatype RecordNumber " +
//					typeRecordNumber + " at " + address);
//				return false;
//			}
//		}
//
//		DataType dataType = applier.getDataType();
//		// Since we know the applier is an AbstractionFunctionTypeApplier, then dataType is either
//		//  FunctionDefinition or no type (typedef).
//		if (dataType instanceof FunctionDefinition) {
//			FunctionDefinition def = (FunctionDefinition) dataType;
//			ApplyFunctionSignatureCmd sigCmd =
//				new ApplyFunctionSignatureCmd(address, def, SourceType.IMPORTED);
//			if (!sigCmd.applyTo(applicator.getProgram(), monitor)) {
//				applicator.appendLogMsg(
//					"PDB Warning: Failed to apply signature to function at address " + address +
//						" due to " + sigCmd.getStatusMsg() + "; dataType: " + def.getName());
//				return false;
//			}
//		}
		return true;
	}

	// Method copied from ApplyStackVariables (ghidra.app.util.bin.format.pdb package)
	//  on 20191119. TODO: Do we need something like this?
	/**
	 * Get the stack offset after it settles down.
	 * @param monitor TaskMonitor
	 * @return stack offset that stack variables will be relative to.
	 * @throws CancelledException upon user cancellation.
	 */
	private int getFrameBaseOffset(Function function, TaskMonitor monitor)
			throws CancelledException {

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
			if (newValue < -(20 * 1024) || newValue > (20 * 1024)) {
				continue;
			}
			if (Math.abs(newValue) > Math.abs(max)) {
				max = newValue;
			}
		}
		return max;
	}

	@Override
	long getStartOffset() {
		return symbol.getDebugStartOffset();
	}

	@Override
	long getEndOffset() {
		return symbol.getDebugEndOffset();
	}

	private boolean isNonReturning() {
		return symbol.getFlags().doesNotReturn();
	}

	private AbstractManagedProcedureMsSymbol getValidatedSymbol(MsSymbolIterator iter,
			boolean iterate) {
		AbstractMsSymbol abstractSymbol = iterate ? iter.next() : iter.peek();
		if (!(abstractSymbol instanceof AbstractManagedProcedureMsSymbol procSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		return procSymbol;
	}

}
