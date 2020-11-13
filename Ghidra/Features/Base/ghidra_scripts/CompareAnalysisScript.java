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
//Script to compare analysis between current and chosen program.
//@category Analysis

import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;

public class CompareAnalysisScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		if (currentAddress == null) {
			println("No Location.");
			return;
		}

		Program otherProgram = askProgram("Choose a program to compare to");
		if (otherProgram == null) {
			return;
		}
		println("\n\n****** COMPARING FUNCTIONS:\n");
		compareFunctions(otherProgram);
		println("\n\n****** COMPARING STRINGS:\n");
		compareStrings(otherProgram);
		println("\n\n****** PERCENT ANALYZED COMPARE SUMMARY:\n");
		reportPercentDisassembled(currentProgram);
		reportPercentDisassembled(otherProgram);
		println("\n\n****** COMPARING SWITCH TABLES:\n");
		compareSwitchTables(otherProgram);
		println("\n\n****** COMPARING NON-RETURNING FUNCTIONS:\n");
		compareNoReturns(otherProgram);
		println("\n\n****** COMPARING ERRORS:\n");
		compareErrors(otherProgram);
	}

	void compareFunctions(Program otherProgram) {
		FunctionManager functionManager = otherProgram.getFunctionManager();
		String currentProgramName = currentProgram.getDomainFile().getName();
		String otherProgramName = otherProgram.getDomainFile().getName();

		Listing listing = currentProgram.getListing();

		int numMissingFuncs = 0;
		int numFuncsInCurrentProg = 0;
		println("Iterating through functions in " + currentProgramName);
		FunctionIterator currentFunctions =
			listing.getFunctions(currentProgram.getMinAddress(), true);
		while (currentFunctions.hasNext() && !monitor.isCancelled()) {
			Function func = currentFunctions.next();
			numFuncsInCurrentProg++;
			Address funcAddress = func.getBody().getMinAddress();
			Function otherFunction = functionManager.getFunctionAt(funcAddress);
			if (otherFunction == null) {
				numMissingFuncs++;
				println(numMissingFuncs + ": Missing function in " + otherProgramName + "  at " +
					funcAddress.toString());
			}

		}

		println("Iterating through functions in " + otherProgramName);
		FunctionManager currentFunctionManager = currentProgram.getFunctionManager();
		int numMissingFuncs2 = 0;
		int numFuncsInOtherProg = 0;
		FunctionIterator otherFunctions =
			otherProgram.getListing().getFunctions(otherProgram.getMinAddress(), true);
		while (otherFunctions.hasNext() && !monitor.isCancelled()) {
			Function otherfunc = otherFunctions.next();
			numFuncsInOtherProg++;
			Address funcAddress = otherfunc.getBody().getMinAddress();
			Function func = currentFunctionManager.getFunctionAt(funcAddress);
			if (func == null) {
				numMissingFuncs2++;
				println(numMissingFuncs2 + ": Missing function in " + currentProgramName + " at " +
					funcAddress.toString());
			}

		}
		println("\n\n****** FUNCTION COMPARE SUMMARY:\n");
		println("There are " + numFuncsInCurrentProg + " functions in " + currentProgramName +
			" and " + numFuncsInOtherProg + " functions in " + otherProgramName);
		println("There are " + numMissingFuncs + " functions missing in " + otherProgramName +
			" that are in " + currentProgramName);
		println("There are " + numMissingFuncs2 + " functions missing in " + currentProgramName +
			" that are in " + otherProgramName);

		return;
	}

	void reportPercentDisassembled(Program prog) throws MemoryAccessException {
		// find all the sections of memory marked as executable
		String programName = prog.getDomainFile().getName();

		AddressSetView execMemSet = prog.getMemory().getExecuteSet();
		/*
		int myExecSetLen = 0;
		MemoryBlock[] blocks = prog.getMemory().getBlocks();
		for (int i = 0; i < blocks.length; i++) {
			if (blocks[i].isExecute()) {
				myExecSetLen += blocks[i].getSize();
			}
		}*/

		// tally up all the bytes that have been marked as instructions
		//   (probably faster ways to do this, but it works)
		long numPossibleDis = execMemSet.getNumAddresses();
		InstructionIterator instIter = prog.getListing().getInstructions(execMemSet, true);
		int instCount = 0;
		while (instIter.hasNext()) {
			Instruction inst = instIter.next();
			instCount += inst.getBytes().length;
		}
		DataIterator dataIter = prog.getListing().getData(execMemSet, true);
		int dataCount = 0;
		while (dataIter.hasNext()) {
			Data data = dataIter.next();
			if (data.isDefined()) {
				dataCount += data.getBytes().length;
			}
		}

		// dump the info
		int total = instCount + dataCount;
		if (numPossibleDis != 0) {
			float coverage = (float) total / (float) numPossibleDis;
//    	Msg.info(this,"execSetLen = " + numPossibleDis);
//    	Msg.info(this,"MyExecSetLen = " + myExecSetLen);
//    	Msg.info(this,"NumInsts = " + instCount);
//    	Msg.info(this,"numData = " + dataCount);
//
//    	Msg.info(this,"totalDis = " + total);
			float percentage = coverage * 100;
			println(programName + ": " + percentage + "% disassembled.");
		}
		return;
	}

	void compareStrings(Program otherProgram) {
		Listing listing = currentProgram.getListing();
		Listing otherListing = otherProgram.getListing();

		String currentProgramName = currentProgram.getDomainFile().getName();
		String otherProgramName = otherProgram.getDomainFile().getName();

		int numMissingStrings = 0;
		int numStringsInCurrentProg = 0;
		println("Iterating through strings in " + currentProgramName);

		DataIterator definedDataIter = listing.getDefinedData(currentProgram.getMinAddress(), true);

		while (definedDataIter.hasNext() && !monitor.isCancelled()) {
			Data currentProgData = definedDataIter.next();

			if (isString(currentProgData.getMnemonicString())) {
				Address stringAddress = currentProgData.getAddress();
				numStringsInCurrentProg++;
				Data otherProgData = otherListing.getDataAt(stringAddress);
				if (otherProgData == null || !isString(otherProgData.getMnemonicString())) {
					numMissingStrings++;
					println(numMissingStrings + ": Missing string in " + otherProgramName +
						"  at " + stringAddress.toString());
				}
			}
		}

		println("Iterating through strings in " + otherProgramName);
		DataIterator otherDataIter =
			otherListing.getDefinedData(otherProgram.getMinAddress(), true);

		int numMissingStrings2 = 0;
		int numStringsInOtherProg = 0;
		while (otherDataIter.hasNext() && !monitor.isCancelled()) {
			Data otherString = otherDataIter.next();
			if (isString(otherString.getMnemonicString())) {
				numStringsInOtherProg++;
				Address otherStringAddress = otherString.getAddress();
				Data currentData = listing.getDataAt(otherStringAddress);

				if (currentData == null || !isString(currentData.getMnemonicString())) {
					numMissingStrings2++;
					println(numMissingStrings2 + ": Missing string in " + currentProgramName +
						" at " + otherStringAddress.toString());
				}
			}

		}
		println("\n\n******STRING COMPARE SUMMARY:\n");
		println("There are " + numStringsInCurrentProg + " strings in " + currentProgramName +
			" and " + numStringsInOtherProg + " strings in " + otherProgramName);
		println("There are " + numMissingStrings + " strings missing in " + otherProgramName +
			" that are in " + currentProgramName);
		println("There are " + numMissingStrings2 + " strings missing in " + currentProgramName +
			" that are in " + otherProgramName);

		return;
	}

	void compareSwitchTables(Program otherProgram) {
		String currentProgramName = currentProgram.getDomainFile().getName();
		String otherProgramName = otherProgram.getDomainFile().getName();

		SymbolTable currentSymbolTable = currentProgram.getSymbolTable();
		SymbolTable otherSymbolTable = otherProgram.getSymbolTable();

		int numMissingSwitches = 0;
		int numSwitchesInCurrentProg = 0;
		println("Iterating through switch tables in " + currentProgramName);

		SymbolIterator currentSymIter = currentSymbolTable.getSymbolIterator("switchdataD_*", true);

		while (currentSymIter.hasNext() && !monitor.isCancelled()) {
			Symbol currentSym = currentSymIter.next();
			Address switchAddress = currentSym.getAddress();
			numSwitchesInCurrentProg++;
			Symbol otherSyms[] = otherSymbolTable.getSymbols(switchAddress);
			if (!isSwitch(otherSyms, "switchdataD_")) {
				numMissingSwitches++;
				println(numMissingSwitches + ": Missing switch table in " + otherProgramName +
					"  at " + switchAddress.toString());
			}
		}

		println("Iterating through switch tables in " + otherProgramName);
		SymbolIterator otherSymIter = otherSymbolTable.getSymbolIterator("switchdataD_*", true);

		int numMissingSwitches2 = 0;
		int numSwitchesInOtherProg = 0;
		while (otherSymIter.hasNext() && !monitor.isCancelled()) {
			Symbol otherSym = otherSymIter.next();
			Address otherSwitchAddress = otherSym.getAddress();
			numSwitchesInOtherProg++;
			Symbol currentSyms[] = currentSymbolTable.getSymbols(otherSwitchAddress);
			if (!isSwitch(currentSyms, "switchdataD_")) {
				numMissingSwitches2++;
				println(numMissingSwitches2 + ": Missing switch table in " + currentProgramName +
					" at " + otherSwitchAddress.toString());
			}
		}

		println("\n\n******SWITCH TABLE COMPARE SUMMARY:\n");
		println(
			"There are " + numSwitchesInCurrentProg + " switch tables in " + currentProgramName +
				" and " + numSwitchesInOtherProg + " switch table in " + otherProgramName);
		println("There are " + numMissingSwitches + " switch tables missing in " +
			otherProgramName + " that are in " + currentProgramName);
		println("There are " + numMissingSwitches2 + " switch tables missing in " +
			currentProgramName + " that are in " + otherProgramName);

		return;
	}

	void compareNoReturns(Program otherProgram) {
		FunctionManager functionManager = otherProgram.getFunctionManager();
		String currentProgramName = currentProgram.getDomainFile().getName();
		String otherProgramName = otherProgram.getDomainFile().getName();

		Listing listing = currentProgram.getListing();

		int numMissingNonReturningFuncs = 0;
		int numNonReturningFuncsInCurrentProg = 0;
		println("Iterating through non-returning functions in " + currentProgramName);
		FunctionIterator currentFunctions =
			listing.getFunctions(currentProgram.getMinAddress(), true);
		while (currentFunctions.hasNext() && !monitor.isCancelled()) {
			Function func = currentFunctions.next();
			if (func.hasNoReturn()) {
				numNonReturningFuncsInCurrentProg++;
				Address funcAddress = func.getBody().getMinAddress();
				Function otherFunction = functionManager.getFunctionAt(funcAddress);
				if (otherFunction == null || !otherFunction.hasNoReturn()) {
					numMissingNonReturningFuncs++;
					println(numMissingNonReturningFuncs +
						": Missing function or function is not marked as non-returning in " +
						otherProgramName + "  at " + funcAddress.toString());
				}

			}

		}

		println("Iterating through non-returning functions in " + otherProgramName);
		FunctionManager currentFunctionManager = currentProgram.getFunctionManager();
		int numMissingNonReturningFuncs2 = 0;
		int numNonReturningFuncsInOtherProg = 0;
		FunctionIterator otherFunctions =
			otherProgram.getListing().getFunctions(otherProgram.getMinAddress(), true);
		while (otherFunctions.hasNext() && !monitor.isCancelled()) {
			Function otherfunc = otherFunctions.next();
			if (otherfunc.hasNoReturn()) {
				numNonReturningFuncsInOtherProg++;
				Address funcAddress = otherfunc.getBody().getMinAddress();
				Function func = currentFunctionManager.getFunctionAt(funcAddress);
				if (func == null || !func.hasNoReturn()) {
					numMissingNonReturningFuncs2++;
					println(numMissingNonReturningFuncs2 +
						": Missing function or function is not marked as non-returning in " +
						currentProgramName + " at " + funcAddress.toString());
				}
			}

		}
		println("\n\n****** NON-RETURNING FUNCTION COMPARE SUMMARY:\n");
		println("There are " + numNonReturningFuncsInCurrentProg + " non-returning functions in " +
			currentProgramName + " and " + numNonReturningFuncsInOtherProg +
			" non-returning functions in " + otherProgramName);
		println(
			"There are " + numMissingNonReturningFuncs + " non-returning functions missing in " +
				otherProgramName + " that are in " + currentProgramName);
		println(
			"There are " + numMissingNonReturningFuncs2 + " non-returning functions missing in " +
				currentProgramName + " that are in " + otherProgramName);

		return;
	}

	void compareErrors(Program otherProgram) {
		BookmarkManager currentBookmarkManager = currentProgram.getBookmarkManager();
		BookmarkManager otherBookmarkManager = otherProgram.getBookmarkManager();
		String currentProgramName = currentProgram.getDomainFile().getName();
		String otherProgramName = otherProgram.getDomainFile().getName();

		int numMissingErrors = 0;
		int numErrorsInCurrentProg = 0;
		println("Iterating through errors in " + currentProgramName);
		Iterator<Bookmark> currentErrorIterator =
			currentBookmarkManager.getBookmarksIterator("Error");

		while (currentErrorIterator.hasNext() && !monitor.isCancelled()) {
			Bookmark error = currentErrorIterator.next();
			numErrorsInCurrentProg++;
			Address errorAddress = error.getAddress();
			Bookmark[] otherErrors = otherBookmarkManager.getBookmarks(errorAddress, "Error");
			if (otherErrors.length == 0) {
				numMissingErrors++;
				println(numMissingErrors + ": No error in " + otherProgramName + "  at " +
					errorAddress.toString());
			}

		}

		println("Iterating through errors in " + otherProgramName);

		int numMissingErrors2 = 0;
		int numErrorsInOtherProg = 0;
		Iterator<Bookmark> otherErrorIterator = otherBookmarkManager.getBookmarksIterator("Error");
		while (otherErrorIterator.hasNext() && !monitor.isCancelled()) {
			Bookmark otherError = otherErrorIterator.next();
			numErrorsInOtherProg++;
			Address otherErrorAddress = otherError.getAddress();
			Bookmark[] currentErrors =
				currentBookmarkManager.getBookmarks(otherErrorAddress, "Error");
			if (currentErrors.length == 0) {
				numMissingErrors2++;
				println(numMissingErrors2 + ": No error in " + currentProgramName + " at " +
					otherErrorAddress.toString());
			}
		}

		println("\n\n****** ERROR COMPARE SUMMARY:\n");
		println("There are " + numErrorsInCurrentProg + " errors in " + currentProgramName +
			" and " + numErrorsInOtherProg + " errors in " + otherProgramName);
		println("There are " + numMissingErrors + " errors not in " + otherProgramName +
			" that are in " + currentProgramName);
		println("There are " + numMissingErrors2 + " errors not in " + currentProgramName +
			" that are in " + otherProgramName);

		return;
	}

	boolean isString(String mnemonic) {

		if (mnemonic.equals(new String("ds")) || mnemonic.equals(new String("unicode")) ||
			mnemonic.equals(new String("p_unicode")) || mnemonic.equals(new String("p_string")) ||
			mnemonic.equals(new String("p_string255")) || mnemonic.equals(new String("mbcs"))) {

			return true;
		}
		return false;
	}

	boolean isSwitch(Symbol[] syms, String name) {
		for (Symbol sym : syms) {
			if (sym.getName().startsWith(name)) {
				return true;
			}
		}
		return false;
	}
}
