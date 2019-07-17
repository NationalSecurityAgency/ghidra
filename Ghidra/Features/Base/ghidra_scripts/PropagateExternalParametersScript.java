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
// This script propagates Windows external and library function parameter names and types
// It puts the parameter names and types in the comments next to the pushes before a function call.
// It currently does not check for branches in the middle of a series of parameters
//@category Analysis

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class PropagateExternalParametersScript extends GhidraScript {
	private List<PushedParamInfo> results = new ArrayList<>();

	@Override
	public void run() throws Exception {
		Listing listing = currentProgram.getListing();
		FunctionManager functionManager = currentProgram.getFunctionManager();
		//FunctionIterator externalFunctions = functionManager.getExternalFunctions();

		ReferenceManager refMan = currentProgram.getReferenceManager();

		// iterate over all external symbols
		SymbolTable symTab = currentProgram.getSymbolTable();
		SymbolIterator externalSymbols = symTab.getExternalSymbols();
		while (externalSymbols.hasNext()) {
			Symbol extSym = externalSymbols.next();
			if (extSym.getSymbolType() == SymbolType.FUNCTION) {
				Function extFunc = functionManager.getFunctionAt(extSym.getAddress());
				Parameter[] params = extFunc.getParameters();
				if (params.length == 0) {
					continue;
				}
				Reference[] references = extSym.getReferences();
				processExternalFunction(listing, refMan, references, extFunc, params,
					extSym.getName());
			}
		}

		// use the 'results' to propagate param info to the local variables, data, and params of 	
		// the calling function
		//println("Processing propagation results - count: " + results.size());
		for (int i = 0; i < results.size(); i++) {
			PushedParamInfo ppi = results.get(i);
			Instruction instr = listing.getInstructionAt(ppi.getAddress());
			int opType = instr.getOperandType(0);

			if (!instr.getOperandRefType(0).isData()) {
				continue;
			}

			//If operand of pushed parameter points to data make a symbol and comment at that location 
			if (((opType & OperandType.ADDRESS) != 0) && (((opType & OperandType.DATA) != 0)) ||
				((opType & OperandType.SCALAR) != 0) || ((opType & OperandType.DYNAMIC) != 0)) {
				Reference[] refs = listing.getCodeUnitAt(ppi.getAddress()).getOperandReferences(0);

				if ((refs.length > 0) && (refs[0].isMemoryReference())) {
					Address dataAddress = refs[0].getToAddress();

					DataType dt = null;
					dt = ppi.getDataType();
					Data data = getDataAt(dataAddress);
					boolean isString = false;
					if ((data != null) && data.hasStringValue()) {
						isString = true;
					}

					String symbolName = new String(ppi.getName() + "_" + dataAddress.toString());
					String newComment = new String(
						ppi.getName() + " parameter of " + ppi.getCalledFunctionName() + "\n");

					if ((getSymbol(symbolName, null) == null) && (isString == false)) {
						createLabel(dataAddress, symbolName, true, SourceType.USER_DEFINED);
					}

					String currentComment = getPlateComment(dataAddress);
					if (currentComment == null) {
						setPlateComment(dataAddress, newComment);
					}
					else if (!currentComment.contains(ppi.getCalledFunctionName())) {
						setPlateComment(dataAddress, currentComment + newComment);
					}

					if ((data != null) &&
						(listing.getCodeUnitAt(dataAddress).getMnemonicString().startsWith(
							"undefined"))) {
						clearListing(dataAddress);
					}
					if (listing.isUndefined(dataAddress, dataAddress.add(dt.getLength() - 1))) {
						try {
							createData(dataAddress, dt);
							printf("Data Created at %s : %s ( %s )\n", dataAddress.toString(),
								newComment.replace("\n", ""), ppi.getAddress().toString());
						}
						catch (Exception e) {
							printf("Error making data: %s", e.toString());
						}
					}

				}

			}

		}

	} // end of run

	private void processExternalFunction(Listing listing, ReferenceManager refMan,
			Reference[] extRefs, Function extFunc, Parameter[] params, String extFuncName) {

		for (Reference extRef : extRefs) {

			Address refAddr = extRef.getFromAddress();

			String refMnemonic = listing.getCodeUnitAt(refAddr).getMnemonicString();
			Function calledFromFunc = listing.getFunctionContaining(refAddr);
			if (calledFromFunc == null) {
				continue;
			}

			if ((refMnemonic.equals(new String("JMP")) && (calledFromFunc.isThunk()))) {
				//println(calledFromFunc.getName() + " is a thunk. Refs are:");
				ReferenceIterator tempIter = refMan.getReferencesTo(calledFromFunc.getEntryPoint());
				while (tempIter.hasNext()) {
					Reference thunkRef = tempIter.next();
					Address thunkRefAddr = thunkRef.getFromAddress();
					String thunkRefMnemonic =
						listing.getCodeUnitAt(thunkRefAddr).getMnemonicString();
					Function thunkRefFunc = listing.getFunctionContaining(thunkRefAddr);
					if ((thunkRefMnemonic.equals(new String("CALL")) && (thunkRefFunc != null))) {
						CodeUnitIterator cuIt =
							getCodeUnitsFromFunctionStartToRef(thunkRefFunc, thunkRefAddr);
						if (checkEnoughPushes(cuIt, params.length)) {
							CodeUnitIterator codeUnitsToRef =
								getCodeUnitsFromFunctionStartToRef(thunkRefFunc, thunkRefAddr);
							propogateParams(params, codeUnitsToRef, extFunc.getName());
							println("Processing external function: " + extFuncName + " at " +
								thunkRefAddr.toString());
						}
					}
				}
			}
			else if ((refMnemonic.equals(new String("CALL")))) {// not a thunk

				CodeUnitIterator cuIt = getCodeUnitsFromFunctionStartToRef(calledFromFunc, refAddr);
				if (checkEnoughPushes(cuIt, params.length)) {
					CodeUnitIterator codeUnitsToRef =
						getCodeUnitsFromFunctionStartToRef(calledFromFunc, refAddr);
					propogateParams(params, codeUnitsToRef, extFunc.getName());
					println("Processing external function: " + extFuncName + " at " +
						refAddr.toString());
				}
			}
		}//end of extRef loop
	}

	/*
	 * Function to skip the parameters of a call that is in the middle of the parameters I am
	 * trying to populate. For example:
	 * PUSH arg 4 to call func1           ; put arg 4 of func1 here
	 * PUSH arg 3 to call func1           ; put arg 3 of func1 here
	 * PUSH arg 3 to call func2 ---|
	 * PUSH arg 2 to call func2    |
	 * PUSH arg 1 to call func2	   | -- want to bypass these
	 * CALL func2               ___|
	 * PUSH arg 2 to call func1           ; put arg2 of func1 here 
	 * PUSH arg 1 to call func1           ; put arg1 of func1 here
	 * CALL func1
	 */

	// get the number of pushes for a code unit if it is a call
	int numParams(CodeUnit cu) {
		FunctionManager functionManager = currentProgram.getFunctionManager();
		Reference[] opref = cu.getReferencesFrom();

		Address toAddr = null;
		Function f = null;
		int numParams = 0;
		if (opref.length != 0) {
			toAddr = opref[0].getToAddress();

			//f = listing.getFunctionAt(toAddr);
			f = functionManager.getReferencedFunction(toAddr);
			if (f != null) {
				//println("Call in middle at " + cu.getMinAddress().toString() + " " + f.getName());
				Parameter[] prms = f.getParameters();
				numParams = prms.length;

			}
		}
		return numParams;
	}

	CodeUnitIterator getCodeUnitsFromFunctionStartToRef(Function func, Address refAddr) {
		if (func == null) {
			return null;
		}

		Listing listing = currentProgram.getListing();
		AddressSetView funcAddresses = func.getBody();
		CodeUnit referenceCodeUnit = listing.getCodeUnitAt(refAddr);
		Address referenceMinAddress = referenceCodeUnit.getMinAddress();

		CodeUnit previousCodeUnit = listing.getCodeUnitBefore(referenceMinAddress);
		Address previousMinAddress = previousCodeUnit.getMinAddress();
		AddressIterator it = funcAddresses.getAddresses(previousMinAddress, false);
		AddressSet addrSet = new AddressSet();
		while (it.hasNext()) {
			Address addr = it.next();
			addrSet.addRange(addr, addr);
		}
		return listing.getCodeUnits(addrSet, false);
	}

	// this will return true if enough pushes before top of function
	// this will return false if not enough pushes or if not a function
	boolean checkEnoughPushes(CodeUnitIterator cuIterator, int numParams) {

		if (cuIterator == null) {
			return false;
		}

		int numPushes = 0;
		int numSkips = 0;
		while ((cuIterator.hasNext()) && (numPushes < numParams)) {
			CodeUnit cu = cuIterator.next();
			if (numSkips > 0) {
				numSkips--;
			}
			else if (cu.getMnemonicString().equals(new String("CALL"))) {
				numParams += numParams(cu);
			}
			else if (cu.getMnemonicString().equals(new String("PUSH"))) {
				numPushes++;
			}
		}

		if (numPushes >= numParams) {
			return true;
		}
		return false; // not enough params between ref and top of function
	}

	void propogateParams(Parameter[] params, CodeUnitIterator cuIt, String extFuncName) {

		int index = 0;
		int numSkips = 0;
		boolean hasBranch = false;

		while (cuIt.hasNext() && (index < params.length) && !hasBranch) {
			CodeUnit cu = cuIt.next();

			// need to take into account calls between the pushes and skip the pushes for those calls
			// skip pushes that are used for another call

			// if label, then probably a branch, allow current push to be commented and 
			// next time through stop
			// can also be a branch if not label there but this case should still have parameters set
			// before it as long as not an unconditional jump - this wouldn't make sense so it shouldn't happen

			if (cu.getLabel() != null) {
				hasBranch = true;
			}

			if (cu.getMnemonicString().equals(new String("CALL"))) {
				numSkips += numParams(cu);
				//printf("numSkips = %d", numSkips);
			}
			else if (cu.getMnemonicString().equals(new String("PUSH"))) {
				if (numSkips > 0) {
					numSkips--;
				}
				else {
					setEOLComment(cu.getMinAddress(), params[index].getDataType().getDisplayName() +
						" " + params[index].getName() + " for " + extFuncName);
					// add the following to the EOL comment to see the value of the optype	
					//	+" " + toHexString(currentProgram.getListing().getInstructionAt(cu.getMinAddress()).getOperandType(0), false, true)
					addResult(params[index].getName(), params[index].getDataType(),
						cu.getMinAddress(), extFuncName);
					index++;
				}
			}

		}
	}

	// for now all calledFuncNames are extFuncNames
	void addResult(String name, DataType dataType, Address addr, String calledFuncName) {
		PushedParamInfo param = new PushedParamInfo(name, dataType, addr, calledFuncName);
		results.add(param);
	}

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
