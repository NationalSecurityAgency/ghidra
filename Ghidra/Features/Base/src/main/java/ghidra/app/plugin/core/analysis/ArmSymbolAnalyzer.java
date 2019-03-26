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
import ghidra.util.exception.AssertException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class ArmSymbolAnalyzer extends AbstractAnalyzer {

	private final static String NAME = "ARM Symbol";
	private final static String DESCRIPTION =
		"Analyze bytes for Thumb symbols and shift -1 as necessary.";

	public ArmSymbolAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// run right before the NoReturn Analyzer
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.before().before().before().before());
		setDefaultEnablement(true);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		monitor.setMessage("ARM/Thumb symbol analyzer");

		Memory memory = program.getMemory();

		// Get and iterate over symbols
		SymbolIterator it = program.getSymbolTable().getPrimarySymbolIterator(set, true);
		while (it.hasNext() && !monitor.isCancelled()) {
			Symbol primarySymbol = it.next();
			Address address = primarySymbol.getAddress();
			if (!address.isMemoryAddress()) {
				continue;
			}

			MemoryBlock block = memory.getBlock(address);
			if (block == null || !block.isExecute()) {
				continue;
			}

			// Check if last bit is set to indicate Thumb
			if ((address.getOffset() & 0x01) != 0x01) {
				continue;
			}

			Address newAddress = address.subtract(1L);

			moveFunction(program, address, newAddress);

			moveSymbols(program, address, newAddress);

			updateEntryPoint(program, address, newAddress);

			setTModeRegister(program, newAddress);

		}
		return true;
	}

	private void setTModeRegister(Program program, Address newAddress) {
		Listing listing = program.getListing();
		Register TModeRegister = program.getRegister("TMode");

		if (listing.getUndefinedDataAt(newAddress) != null) {
			try {
				program.getProgramContext().setValue(TModeRegister, newAddress, newAddress,
					new BigInteger("1"));
			}
			catch (ContextChangeException e) {
				Msg.error(this, "Unexpected Error", e);
			}
		}
	}

	private void updateEntryPoint(Program program, Address address, Address newAddress) {
		SymbolTable symbolTable = program.getSymbolTable();
		if (symbolTable.isExternalEntryPoint(address) == true) {
			// Remove old entry point and add new one
			symbolTable.removeExternalEntryPoint(address);
			symbolTable.addExternalEntryPoint(newAddress);
		}
	}

	private void moveSymbols(Program program, Address address, Address newAddress) {
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol primary = symbolTable.getPrimarySymbol(address);
		if (primary == null || primary.getSource() == SourceType.DEFAULT) {
			return;
		}

		createLabel(symbolTable, newAddress, primary.getName(), primary.getSource());

		Symbol[] symbols = symbolTable.getSymbols(address);
		for (Symbol s : symbols) {
			if (s != primary) {
				createLabel(symbolTable, newAddress, s.getName(), s.getSource());
				s.delete();
			}
		}
		primary.delete();
	}

	private void moveFunction(Program program, Address address, Address newAddress) {
		FunctionManager functionManager = program.getFunctionManager();
		Function func = functionManager.getFunctionAt(address);
		if (func != null) {
			// make sure no function at current and new location
			//  can't change primary if it is there.
			functionManager.removeFunction(address);
			functionManager.removeFunction(newAddress);

			try {
				AddressSet body = new AddressSet(newAddress);
				functionManager.createFunction(null, newAddress, body, SourceType.DEFAULT);
			}
			catch (InvalidInputException | OverlappingFunctionException e) {
				Msg.error(this, "Error creating function", e);
			}
		}
	}

	private void createLabel(SymbolTable symbolTable, Address address, String name,
			SourceType sourceType) {

		try {
			symbolTable.createLabel(address, name, sourceType);
		}
		catch (InvalidInputException e) {
			// the name came from an existing symbol, so the name should be valid!
			throw new AssertException("This should never happen!", e);
		}
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
			Processor.findOrPossiblyCreateProcessor("ARM")) &&
			program.getRegister("TMode") != null);
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
