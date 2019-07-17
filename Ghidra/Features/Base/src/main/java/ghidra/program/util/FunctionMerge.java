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
package ghidra.program.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.datastruct.LongLongHashtable;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class FunctionMerge {

	private AddressTranslator originToResultTranslator;
	private Program fromProgram;
	private Program toProgram;
	private FunctionManager fromFunctionManager;
	private FunctionManager toFunctionManager;

	public FunctionMerge(AddressTranslator originToResultTranslator) {
		this.originToResultTranslator = originToResultTranslator;
		this.fromProgram = originToResultTranslator.getSourceProgram();
		this.toProgram = originToResultTranslator.getDestinationProgram();
		this.fromFunctionManager = fromProgram.getFunctionManager();
		this.toFunctionManager = toProgram.getFunctionManager();
	}

	Symbol replaceFunctionSymbol(Address originEntryPoint, LongLongHashtable conflictSymbolIDMap,
			TaskMonitor monitor)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {

		// Assumes: The function in the destination program should already be replaced at this point.
		Address resultEntryPoint = originToResultTranslator.getAddress(originEntryPoint);
		Function fromFunction = fromFunctionManager.getFunctionAt(originEntryPoint);
		Function toFunction = toFunctionManager.getFunctionAt(resultEntryPoint);
		if ((fromFunction != null) && (toFunction != null)) {
			String fromName = fromFunction.getName();
			Symbol fromSymbol = fromFunction.getSymbol();
			SourceType fromSource = fromSymbol.getSource();
			Namespace fromNamespace = fromSymbol.getParentNamespace();
			Namespace expectedToNamespace = DiffUtility.getNamespace(fromNamespace, toProgram);
			if (expectedToNamespace != null) {
				Symbol existingSymbol = toProgram.getSymbolTable().getSymbol(fromName,
					originEntryPoint, expectedToNamespace);
				if (existingSymbol != null) {
					// TODO Change the function symbol to this one. // FIXME
				}
			}
			String toName = toFunction.getName();
			Symbol toSymbol = toFunction.getSymbol();
			Namespace currentToNamespace = toSymbol.getParentNamespace();
			Symbol expectedNamespaceSymbol =
				SimpleDiffUtility.getSymbol(fromNamespace.getSymbol(), toProgram);
			boolean sameNamespace = currentToNamespace.getSymbol() == expectedNamespaceSymbol;
			if (fromName.equals(toName) && sameNamespace) {
				return toSymbol; // function symbol name and namespace match.
			}
			Namespace desiredToNamespace = currentToNamespace;
			if (!sameNamespace) {
				desiredToNamespace = new SymbolMerge(fromProgram, toProgram).resolveNamespace(
					fromNamespace, conflictSymbolIDMap);
			}
			// Rename the function so that we will be able to move it.
			boolean hasDifferentName = !fromName.equals(toName);
			if (hasDifferentName) {
				toFunction.setName(fromName, fromSource);
			}
			// Move it to the new namespace.
			if (currentToNamespace != desiredToNamespace) {
				toFunction.setParentNamespace(desiredToNamespace);
			}

			// TODO May want to save the symbol info if the function didn't get desired pathname. // FIXME

			return toFunction.getSymbol();
		}
		return null;
	}

	static Symbol replaceFunctionSymbol(Program fromProgram, Program toProgram, Address entryPoint,
			LongLongHashtable conflictSymbolIDMap, TaskMonitor monitor)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		// Assumes: The function in the destination program should already be replaced at this point.
		FunctionManager fromFunctionMgr = fromProgram.getFunctionManager();
		FunctionManager toFunctionMgr = toProgram.getFunctionManager();
		Function fromFunc = fromFunctionMgr.getFunctionAt(entryPoint);
		Function toFunc = toFunctionMgr.getFunctionAt(entryPoint);
		if ((fromFunc != null) && (toFunc != null)) {
			String fromName = fromFunc.getName();
			Symbol fromSymbol = fromFunc.getSymbol();
			SourceType source = fromSymbol.getSource();
			Namespace fromNamespace = fromSymbol.getParentNamespace();
			Namespace expectedToNamespace = DiffUtility.getNamespace(fromNamespace, toProgram);
			if (expectedToNamespace != null) {
				Symbol existingSymbol =
					toProgram.getSymbolTable().getSymbol(fromName, entryPoint, expectedToNamespace);
				if (existingSymbol != null) {
					// TODO Change the function symbol to this one. // FIXME
				}
			}
			String toName = toFunc.getName();
			Symbol toSymbol = toFunc.getSymbol();
			Namespace currentToNamespace = toSymbol.getParentNamespace();
			Symbol expectedNamespaceSymbol =
				SimpleDiffUtility.getSymbol(fromNamespace.getSymbol(), toProgram);
			boolean sameNamespace = currentToNamespace.getSymbol() == expectedNamespaceSymbol;
			if (fromName.equals(toName) && sameNamespace) {
				return toSymbol; // function symbol name and namespace match.
			}
			Namespace desiredToNamespace = currentToNamespace;
			if (!sameNamespace) {
				desiredToNamespace = new SymbolMerge(fromProgram, toProgram).resolveNamespace(
					fromNamespace, conflictSymbolIDMap);
			}
			// Rename the function so that we will be able to move it.
			boolean hasDifferentName = !fromName.equals(toName);
			if (hasDifferentName) {
				toFunc.setName(fromName, source);
			}
			// Move it to the new namespace.
			if (currentToNamespace != desiredToNamespace) {
				toFunc.setParentNamespace(desiredToNamespace);
			}

			// TODO May want to save the symbol info if the function didn't get desired pathname. // FIXME

			return toFunc.getSymbol();
		}
		return null;
	}

	public void replaceFunctionsNames(AddressSetView originAddressSet, TaskMonitor monitor)
			throws CancelledException {
		FunctionIterator originIter = fromFunctionManager.getFunctions(originAddressSet, true);
		LongLongHashtable conflictSymbolIDMap = new LongLongHashtable();
		monitor.setMessage("Replacing function names...");
		int max = (int) originAddressSet.getNumAddresses();
		monitor.initialize(max);
		int count = 0;
		while (originIter.hasNext()) {
			monitor.setProgress(++count);
			monitor.checkCanceled();
			Function originFunction = originIter.next();
			Address originEntryPoint = originFunction.getEntryPoint();
			Address resultEntryPoint = originToResultTranslator.getAddress(originEntryPoint);
			monitor.setMessage("Replacing function name " + count + " of " + max + ".  Address=" +
				originEntryPoint.toString(true));
			Function resultFunction = toFunctionManager.getFunctionAt(resultEntryPoint);
			if (resultFunction != null &&
				!resultFunction.getName().equals(originFunction.getName())) {
				try {
					replaceFunctionSymbol(originEntryPoint, conflictSymbolIDMap, monitor);
				}
				catch (DuplicateNameException e) {
				}
				catch (InvalidInputException e) {
				}
				catch (CircularDependencyException e) {
					// TODO MAy want message to user if can't replace name.
				}
			}
		}
		monitor.setProgress(max);
	}

	public static void replaceFunctionsNames(ProgramMerge pgmMerge, AddressSetView addressSet,
			TaskMonitor monitor) throws CancelledException {
		Program resultProgram = pgmMerge.getResultProgram();
		Program originProgram = pgmMerge.getOriginProgram();
		FunctionManager resultFM = resultProgram.getFunctionManager();
		FunctionManager originFM = originProgram.getFunctionManager();
		FunctionIterator iter = resultFM.getFunctions(addressSet, true);
		LongLongHashtable conflictSymbolIDMap = new LongLongHashtable();
		monitor.setMessage("Replacing function names...");
		long max = addressSet.getNumAddresses();
		monitor.initialize(max);
		int count = 0;
		while (iter.hasNext()) {
			monitor.setProgress(++count);
			monitor.checkCanceled();
			Function resultFunction = iter.next();
			Address resultEntryPt = resultFunction.getEntryPoint();
			monitor.setMessage("Replacing function name " + count + " of " + max + ".  Address=" +
				resultEntryPt.toString(true));
			Function originFunction = originFM.getFunctionAt(resultEntryPt);
			if (originFunction != null &&
				!resultFunction.getName().equals(originFunction.getName())) {
				try {
					replaceFunctionSymbol(originProgram, resultProgram, resultEntryPt,
						conflictSymbolIDMap, monitor);
				}
				catch (DuplicateNameException e) {
				}
				catch (InvalidInputException e) {
				}
				catch (CircularDependencyException e) {
					// TODO MAy want message to user if can't replace name.
				}
			}
		}
		monitor.setProgress(max);
	}

}
