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
			// can't handle reversion to DEFAULT - use existing function if fromSymbol is DEFAULT
			if (fromSource == SourceType.DEFAULT) {
				return toFunction.getSymbol();
			}
			Namespace fromNamespace = fromSymbol.getParentNamespace();
			Namespace expectedToNamespace = DiffUtility.getNamespace(fromNamespace, toProgram);
			if (expectedToNamespace != null) {
				Symbol existingSymbol = toProgram.getSymbolTable().getSymbol(fromName,
					originEntryPoint, expectedToNamespace);
				if (existingSymbol != null) {
					if (!existingSymbol.isPrimary()) {
						existingSymbol.setPrimary();
					}
					return existingSymbol;
				}
			}
			String toName = toFunction.getName();
			Symbol toSymbol = toFunction.getSymbol();
			SourceType toSource = toSymbol.getSource();
			boolean toDefault = toSource == SourceType.DEFAULT;
			Namespace currentToNamespace = // default thunks will lie about their namespace
				toDefault ? toFunction.getProgram().getGlobalNamespace()
						: toSymbol.getParentNamespace();
			Symbol expectedNamespaceSymbol =
				SimpleDiffUtility.getSymbol(fromNamespace.getSymbol(), toProgram);
			boolean sameNamespace = currentToNamespace.getSymbol() == expectedNamespaceSymbol;
			if (!toDefault && fromName.equals(toName) && sameNamespace) {
				return toSymbol; // function symbol name and namespace match.
			}
			Namespace desiredToNamespace = currentToNamespace;
			if (!sameNamespace) {
				desiredToNamespace = new SymbolMerge(fromProgram, toProgram).resolveNamespace(
					fromNamespace, conflictSymbolIDMap);
			}

			// Move it to the new namespace.
			if (currentToNamespace != desiredToNamespace) {
				toFunction.setParentNamespace(desiredToNamespace);
			}

			// Rename the function so that we will be able to move it.
			boolean hasDifferentName = !fromName.equals(toName);
			if (hasDifferentName) {
				toFunction.setName(fromName, fromSource);
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
		Function fromFunction = fromFunctionMgr.getFunctionAt(entryPoint);
		Function toFunction = toFunctionMgr.getFunctionAt(entryPoint);
		if ((fromFunction != null) && (toFunction != null)) {
			String fromName = fromFunction.getName();
			Symbol fromSymbol = fromFunction.getSymbol();
			SourceType fromSource = fromSymbol.getSource();
			// can't handle reversion to DEFAULT - use existing function if fromSymbol is DEFAULT
			if (fromSource == SourceType.DEFAULT) {
				return toFunction.getSymbol();
			}
			Namespace fromNamespace = fromSymbol.getParentNamespace();
			Namespace expectedToNamespace = DiffUtility.getNamespace(fromNamespace, toProgram);
			if (expectedToNamespace != null) {
				Symbol existingSymbol =
					toProgram.getSymbolTable().getSymbol(fromName, entryPoint, expectedToNamespace);
				if (existingSymbol != null) {
					if (!existingSymbol.isPrimary()) {
						existingSymbol.setPrimary();
					}
					return existingSymbol;
				}
			}
			String toName = toFunction.getName();
			Symbol toSymbol = toFunction.getSymbol();
			SourceType toSource = toSymbol.getSource();
			boolean toDefault = toSource == SourceType.DEFAULT;
			Namespace currentToNamespace = // default thunks will lie about their namespace
				toDefault ? toFunction.getProgram().getGlobalNamespace()
						: toSymbol.getParentNamespace();
			Symbol expectedNamespaceSymbol =
				SimpleDiffUtility.getSymbol(fromNamespace.getSymbol(), toProgram);
			boolean sameNamespace = currentToNamespace.getSymbol() == expectedNamespaceSymbol;
			if (!toDefault && fromName.equals(toName) && sameNamespace) {
				return toSymbol; // function symbol name and namespace match.
			}
			Namespace desiredToNamespace = currentToNamespace;
			if (!sameNamespace) {
				desiredToNamespace = new SymbolMerge(fromProgram, toProgram).resolveNamespace(
					fromNamespace, conflictSymbolIDMap);
			}

			// Move it to the new namespace.
			if (currentToNamespace != desiredToNamespace) {
				toFunction.setParentNamespace(desiredToNamespace);
			}

			// Rename the function so that we will be able to move it.
			boolean hasDifferentName = !fromName.equals(toName);
			if (hasDifferentName) {
				toFunction.setName(fromName, fromSource);
			}

			// TODO May want to save the symbol info if the function didn't get desired pathname. // FIXME

			return toFunction.getSymbol();
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
			SourceType originSource = originFunction.getSymbol().getSource();
			Address originEntryPoint = originFunction.getEntryPoint();
			Address resultEntryPoint = originToResultTranslator.getAddress(originEntryPoint);
			monitor.setMessage("Replacing function name " + count + " of " + max);
			Function resultFunction = toFunctionManager.getFunctionAt(resultEntryPoint);
			if (resultFunction != null) {
				// TODO: Gets complicated if 
				SourceType resultSource = resultFunction.getSymbol().getSource();
				if (resultSource == SourceType.DEFAULT && originSource == SourceType.DEFAULT) {
					continue;
				}
				if (!resultFunction.getName().equals(originFunction.getName())) {
					try {
						replaceFunctionSymbol(originEntryPoint, conflictSymbolIDMap, monitor);
					}
					catch (DuplicateNameException e) {
					}
					catch (InvalidInputException e) {
					}
					catch (CircularDependencyException e) {
						// TODO May want message to user if can't replace name.
					}
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
