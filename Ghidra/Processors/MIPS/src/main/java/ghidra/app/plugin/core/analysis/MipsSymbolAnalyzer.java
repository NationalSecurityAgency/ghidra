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
package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class MipsSymbolAnalyzer extends AbstractAnalyzer {

	private final static String NAME = "MIPS Symbol";
	private final static String DESCRIPTION =
		"Analyze bytes for Mips16 symbols and shift -1 as necessary.";

	public MipsSymbolAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// run right before the NoReturn Analyzer
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.before().before().before().before());
		setDefaultEnablement(true);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		monitor.setMessage("Mips16 symbol analyzer");

		// Get ISA_MODE register
		Register IsaModeRegister = program.getRegister("ISA_MODE");

		Memory memory = program.getMemory();

		Listing listing = program.getListing();

		FunctionManager functionManager = program.getFunctionManager();
		AddressSet redo = new AddressSet();

		// Get and iterate over symbols
		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator allSymbolsIter = symbolTable.getAllSymbols(true);
		while (allSymbolsIter.hasNext() && !monitor.isCancelled()) {
			Symbol symbol = allSymbolsIter.next();
			Address memAddr = symbol.getAddress();

			SourceType source = symbol.getSource();
			if (source != SourceType.IMPORTED) {
				continue;
			}

			// Only care if memory address
			if (memAddr.isMemoryAddress()) {

				MemoryBlock block = memory.getBlock(memAddr);
				if (block == null || !block.isExecute()) {
					continue;
				}

				// Check if last bit is set to indicate mips16
				if ((memAddr.getOffset() & 0x01) == 0x01) {
					Address newAddr = memAddr.subtract(1L);

					String name = symbol.getName();

					// Remove symbol
					symbolTable.removeSymbolSpecial(symbol);

					Function func = functionManager.getFunctionAt(memAddr);
					boolean isFunc = func != null;
					if (isFunc) {
						// make sure no function at current and new location
						//  can't change primary if it is there.
						functionManager.removeFunction(memAddr);
						functionManager.removeFunction(newAddr);
					}

					// Add new symbol at address-1
					// (symbol has been removed from symbolTable, but the current
					// "symbol" instance has not been lost yet, so we can still use it)
					try {
						symbol = symbolTable.createLabel(newAddr, name, source);
						// if there was a function there, need to put it back.
						if (isFunc) {
							symbol.setPrimary();
							AddressSet body = new AddressSet(newAddr);
							try {
								functionManager.createFunction(null, newAddr, body, source);
							}
							catch (OverlappingFunctionException e) {
							}
						}
					}
					catch (InvalidInputException e) {
					}

					// Check if entry point.
					if (symbolTable.isExternalEntryPoint(memAddr) == true) {
						// Remove old entry point and add new one
						symbolTable.removeExternalEntryPoint(memAddr);
						symbolTable.addExternalEntryPoint(newAddr);

					}

					// Set ISA_MODE register to 1
					if (listing.getUndefinedDataAt(newAddr) != null) {
						try {
							program.getProgramContext().setValue(IsaModeRegister, newAddr, newAddr,
								new BigInteger("1"));

							redo.add(newAddr);
						}
						catch (ContextChangeException e) {
							Msg.error(this, "Unexpected Error", e);
						}
					}
				}
			}
		}

		if (!redo.isEmpty()) {
			AutoAnalysisManager.getAnalysisManager(program).reAnalyzeAll(redo);
		}

		return true;
	}

	@Override
	public void analysisEnded(Program program) {
		// After run once, set analyzer off in analyzer options

		/*
		options options = program.getPropertyList("Analyzers");
		options.setValue(name, false);
		*/
	}

	@Override
	public boolean canAnalyze(Program program) {
		// Check language
		return (program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor("MIPS")) &&
			program.getRegister("ISA_MODE") != null);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		// Since only want this analyzer to run once, check if there are already instructions
		// if there are, return false

		/*
		if ( program.getListing().getNumInstructions() != 0 )
			return false;
		*/

		// Otherwise, return true
		return true;
	}

}
