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
package ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class PropagateExternalParametersAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "WindowsPE x86 Propagate External Parameters";
	private static final String DESCRIPTION =
		"This analyzer uses external Windows function call parameter information to populate " +
			"comments next to pushed parameters. In some cases, data is labeled and commented as well";
	private List<PushedParamInfo> results = new ArrayList<>();
	private Program currentProgram;

	public PropagateExternalParametersAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setSupportsOneTimeAnalysis();
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after().after().after());
		//	setPrototype();

	}

	private void processExternalFunction(Listing listing, ReferenceManager refMan,
			Reference[] extRefs, Function externalFunction, Parameter[] params) {

		String externalFunctionName = externalFunction.getName();
		for (Reference extRef : extRefs) {

			Address fromAddr = extRef.getFromAddress();
			Function callingFunction = listing.getFunctionContaining(fromAddr);
			if (callingFunction == null) {
				continue;
			}

			String mnemonic = listing.getCodeUnitAt(fromAddr).getMnemonicString();
			if ((mnemonic.equals("JMP") && (callingFunction.isThunk()))) {
				processThunkReference(listing, refMan, externalFunction, params, callingFunction);
			}
			else if ((mnemonic.equals("CALL"))) {// not a thunk
				CodeUnitIterator it = getCodeUnitsFromFunctionStartToRef(callingFunction, fromAddr);
				if (hasEnoughPushes(it, params.length)) {
					CodeUnitIterator codeUnitsToRef =
						getCodeUnitsFromFunctionStartToRef(callingFunction, fromAddr);
					propogateParams(params, codeUnitsToRef, externalFunctionName);
				}
			}
		}
	}

	private void processThunkReference(Listing listing, ReferenceManager refMan,
			Function externalFunction, Parameter[] params, Function callingFunction) {
		ReferenceIterator iterator = refMan.getReferencesTo(callingFunction.getEntryPoint());
		for (Reference thunkRef : iterator) {
			Address thunkAddr = thunkRef.getFromAddress();
			Function thunk = listing.getFunctionContaining(thunkAddr);
			if (thunk == null) {
				continue;
			}

			String thunkMnemonic = listing.getCodeUnitAt(thunkAddr).getMnemonicString();
			if (!thunkMnemonic.equals("CALL")) {
				continue;
			}

			CodeUnitIterator cuIt = getCodeUnitsFromFunctionStartToRef(thunk, thunkAddr);
			if (hasEnoughPushes(cuIt, params.length)) {
				CodeUnitIterator codeUnitsToRef =
					getCodeUnitsFromFunctionStartToRef(thunk, thunkAddr);
				propogateParams(params, codeUnitsToRef, externalFunction.getName());
			}
		}
	}

// * Function to skip the parameters of a call that is in the middle of the parameters I am
// * trying to populate. For example:
// * PUSH arg 4 to call func1           ; put arg 4 of func1 here
// * PUSH arg 3 to call func1           ; put arg 3 of func1 here
// * PUSH arg 3 to call func2 ---|
// * PUSH arg 2 to call func2    |
// * PUSH arg 1 to call func2	   | -- want to bypass these
// * CALL func2               ___|
// * PUSH arg 2 to call func1           ; put arg2 of func1 here
// * PUSH arg 1 to call func1           ; put arg1 of func1 here
// * CALL func1

// get the number of pushes for a code unit if it is a call
	private int numParams(CodeUnit cu) {

		Reference[] references = cu.getReferencesFrom();
		if (references.length != 0) {
			Address toAddr = references[0].getToAddress();
			FunctionManager functionManager = currentProgram.getFunctionManager();
			Function f = functionManager.getReferencedFunction(toAddr);
			if (f != null) {
				Parameter[] params = f.getParameters();
				return params.length;
			}
		}
		return 0;
	}

	private CodeUnitIterator getCodeUnitsFromFunctionStartToRef(Function function,
			Address referenceAddress) {
		if (function == null) {
			return null;
		}

		Listing listing = currentProgram.getListing();
		AddressSetView functionBody = function.getBody();
		CodeUnit referenceCodeUnit = listing.getCodeUnitAt(referenceAddress);
		Address referenceMinAddress = referenceCodeUnit.getMinAddress();

		CodeUnit previousCodeUnit = listing.getCodeUnitBefore(referenceMinAddress);
		Address previousMinAddress = previousCodeUnit.getMinAddress();
		AddressIterator it = functionBody.getAddresses(previousMinAddress, false);
		AddressSet addrSet = new AddressSet();
		while (it.hasNext()) {
			Address addr = it.next();
			addrSet.addRange(addr, addr);
		}
		return listing.getCodeUnits(addrSet, false);
	}

	/**
	 * This will return true if enough pushes before top of function.
	 * This will return false if not enough pushes or if not a function.
	 */
	private boolean hasEnoughPushes(CodeUnitIterator iterator, int numParams) {

		if (iterator == null) {
			return false;
		}

		int numPushes = 0;
		int numSkips = 0;
		while ((iterator.hasNext()) && (numPushes < numParams)) {
			CodeUnit cu = iterator.next();
			if (numSkips > 0) {
				numSkips--;
			}
			else if (cu.getMnemonicString().equals("CALL")) {
				numParams += numParams(cu);
			}
			else if (cu.getMnemonicString().equals("PUSH")) {
				numPushes++;
			}
		}

		// Have enough params between ref and top of function?
		return numPushes >= numParams;
	}

	private void propogateParams(Parameter[] params, CodeUnitIterator iterator,
			String externalFunctionName) {

		int index = 0;
		int numSkips = 0;
		while (iterator.hasNext() && index < params.length) {

			// Need to take into account calls between the pushes and skip the
			// pushes for those calls skip pushes that are used for another call.

			// If label, then probably a branch, allow current push to be commented and
			// next time through stop.  Can also be a branch if not label there but
			// this case should still have parameters set
			// before it as long as not an unconditional jump - this wouldn't make
			// sense so it shouldn't happen

			CodeUnit cu = iterator.next();
			boolean isBranch = cu.getLabel() != null;

			if (cu.getMnemonicString().equals("CALL")) {
				numSkips += numParams(cu);
			}
			else if (cu.getMnemonicString().equals("PUSH")) {
				if (numSkips > 0) {
					numSkips--;
				}
				else {
					Parameter param = params[index];
					DataType dt = param.getDataType();
					String name = param.getName();
					SetCommentCmd cmd = new SetCommentCmd(cu.getAddress(), CodeUnit.EOL_COMMENT,
						dt.getDisplayName() + " " + name + " for " + externalFunctionName);
					cmd.applyTo(currentProgram);

					// add the following to the EOL comment to see the value of the optype
					addResult(name, dt, cu.getMinAddress(), externalFunctionName);
					index++;
				}
			}

			if (isBranch) {
				break;
			}
		}
	}

	// for now all calledFuncNames are extFuncNames -might change if I add others later
	private void addResult(String name, DataType dataType, Address addr, String calledFuncName) {
		PushedParamInfo param = new PushedParamInfo(name, dataType, addr, calledFuncName);
		results.add(param);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return PEUtil.canAnalyze(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		this.currentProgram = program;

		Listing listing = program.getListing();
		FunctionManager functionManager = program.getFunctionManager();
		ReferenceManager referenceManager = program.getReferenceManager();

		// iterate over all external symbols
		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator externalSymbols = symbolTable.getExternalSymbols();
		for (Symbol externalSymbol : externalSymbols) {
			if (externalSymbol.getSymbolType() != SymbolType.FUNCTION) {
				continue;
			}

			Function externalFunction = functionManager.getFunctionAt(externalSymbol.getAddress());
			Parameter[] params = externalFunction.getParameters();
			if (params.length == 0) {
				continue;
			}

			Reference[] references = externalSymbol.getReferences();
			processExternalFunction(listing, referenceManager, references, externalFunction,
				params);
		}

		// use the 'results' to propagate param info to the local variables, data, and params of
		// the calling function
		Msg.trace(this, "Processing propagation results - count: " + results.size());
		for (int i = 0; i < results.size(); i++) {
			PushedParamInfo paramInfo = results.get(i);
			Address paramAddress = paramInfo.getAddress();
			Instruction instruction = listing.getInstructionAt(paramAddress);

			// wait on applying data types - the microsoft analyzer does some of this
			// see how much/well it does first
			if (!instruction.getOperandRefType(0).isData()) {
				continue;
			}

			int opType = instruction.getOperandType(0);
			if (!isAddressReferenceOperand(opType)) {
				continue;
			}

			Address referencedAddress = getReferencedAddress(paramAddress);
			if (referencedAddress == null) {
				continue;
			}

			String paramName = paramInfo.getName();
			String symbolName = paramName + "_" + referencedAddress.toString();

			addSymbol(symbolTable, referencedAddress, symbolName);

			String paramText = paramName + " parameter of " + paramInfo.getCalledFunctionName();
			String newComment = paramText + "\n";
			Msg.trace(this, "External Function Call at " + paramAddress + " : " + paramText +
				" at " + referencedAddress.toString());

			createComment(referencedAddress, newComment, paramInfo);

			clearUndefinedDataType(referencedAddress, monitor);

			createData(paramInfo, referencedAddress);
		}

		return true;
	}

	private void createComment(Address dataAddress, String newComment, PushedParamInfo info) {
		Listing listing = currentProgram.getListing();
		String plateComment = listing.getComment(CodeUnit.PLATE_COMMENT, dataAddress);
		if (plateComment == null) {
			// add a comment
			SetCommentCmd cmd = new SetCommentCmd(dataAddress, CodeUnit.PLATE_COMMENT, newComment);
			cmd.applyTo(currentProgram);
		}
		else if (!plateComment.contains(info.getCalledFunctionName())) {
			// update the existing comment
			String updatedComment = plateComment + "\n" + newComment;
			SetCommentCmd cmd =
				new SetCommentCmd(dataAddress, CodeUnit.PLATE_COMMENT, updatedComment);
			cmd.applyTo(currentProgram);
		}
	}

	private void createData(PushedParamInfo paramInfo, Address address) {

		Listing listing = currentProgram.getListing();
		DataType dt = paramInfo.getDataType();
		if (!listing.isUndefined(address, address.add(dt.getLength() - 1))) {
			return; // don't overwrite existing data
		}

		CreateDataCmd cmd = new CreateDataCmd(address, dt);
		if (!cmd.applyTo(currentProgram)) {
			Msg.error(this, "Error making data: " + cmd.getStatusMsg());
		}
	}

	private void clearUndefinedDataType(Address address, TaskMonitor monitor)
			throws CancelledException {

		Listing listing = currentProgram.getListing();
		Data data = listing.getDefinedDataAt(address);
		if (data == null) {
			return;
		}

		DataType dt = data.getDataType();
		if (Undefined.isUndefined(dt)) {
			listing.clearCodeUnits(address, address, false, monitor);
		}
	}

	private void addSymbol(SymbolTable symbolTable, Address address, String symbolName) {

		Listing listing = currentProgram.getListing();
		Data data = listing.getDefinedDataAt(address);
		if (data != null && data.hasStringValue()) {
			return; // don't add symbol for string (not sure why)
		}

		try {
			Symbol newSymbol =
				symbolTable.createLabel(address, symbolName, SourceType.USER_DEFINED);
			newSymbol.setPrimary();
		}
		catch (InvalidInputException e) {
			// shouldn't happen
			Msg.trace(this, "Unexpected exception", e);
		}

	}

	private Address getReferencedAddress(Address address) {
		Listing listing = currentProgram.getListing();
		Reference[] refs = listing.getCodeUnitAt(address).getOperandReferences(0);
		if ((refs.length > 0) && (refs[0].isMemoryReference())) {
			return refs[0].getToAddress();
		}
		return null;
	}

	private boolean isAddressReferenceOperand(int opType) {
		if ((opType & OperandType.ADDRESS) == 0) {
			return false;
		}

		//@formatter:off
		return ((opType & OperandType.DATA) != 0)   ||
			   ((opType & OperandType.SCALAR) != 0) ||
			   ((opType & OperandType.DYNAMIC) != 0);
		//@formatter:on
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	// info about the pushed parameter that gets applied to the calling functions params and locals and referenced data
	private class PushedParamInfo {
		private String name;
		private DataType dataType;
		private Address addr;
		private String calledFunctionName;

		PushedParamInfo(String name, DataType dataType, Address addr, String calledFunctionName) {
			this.name = name;
			this.dataType = dataType;
			this.addr = addr;
			this.calledFunctionName = calledFunctionName;
		}

		String getName() {
			return name;
		}

		DataType getDataType() {
			return dataType;
		}

		Address getAddress() {
			return addr;
		}

		String getCalledFunctionName() {
			return calledFunctionName;
		}
	}
}
