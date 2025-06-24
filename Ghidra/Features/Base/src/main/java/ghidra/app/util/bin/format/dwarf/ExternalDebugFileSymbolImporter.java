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
package ghidra.app.util.bin.format.dwarf;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Imports symbols from an external debug program (typically created via a reverse strip) into
 * the program that contains the executable code that the symbols will be applied to.
 */
public class ExternalDebugFileSymbolImporter {

	private Program program;
	private Program externalDebugProgram;
	private SymbolTable symTable;
	private FunctionManager funcMgr;
	private SymbolTable extSymTable;

	private TaskMonitor monitor;

	private int funcSymbolsCopied;
	private int dataSymbolsCopied;
	private int symbolsSkipped;
	private int totalSymbolCount;

	public ExternalDebugFileSymbolImporter(Program program, Program externalDebugProgram,
			TaskMonitor monitor) {
		this.program = program;
		this.externalDebugProgram = externalDebugProgram;
		this.monitor = monitor;

		this.symTable = program.getSymbolTable();
		this.funcMgr = program.getFunctionManager();

		this.extSymTable = externalDebugProgram.getSymbolTable();
	}

	public void importSymbols(MessageLog log) throws CancelledException {
		if (!isSameMemmap()) {
			Msg.warn(this,
				"Unable to copy external symbols from external debug file, memory map does not match");
			return;
		}

		try {
			monitor.setIndeterminate(false);
			monitor.initialize(extSymTable.getNumSymbols(), "External debug file symbols");
			for (Symbol extSym : extSymTable.getPrimarySymbolIterator(true)) {
				monitor.increment();
				totalSymbolCount++;
				if (shouldCopyExtSymbol(extSym)) {
					copyExtSymbol(extSym);
				}
			}
		}
		catch (InvalidInputException | CodeUnitInsertionException
				| OverlappingFunctionException e) {
			log.appendMsg("Error while copying external debug file symbols");
			log.appendException(e);
		}
		finally {

			Msg.info(this, "Copied %d/%d of %d func/data/total symbols from external debug file"
					.formatted(funcSymbolsCopied, dataSymbolsCopied, totalSymbolCount));
		}
	}

	private void copyExtSymbol(Symbol extSym)
			throws InvalidInputException, OverlappingFunctionException, CodeUnitInsertionException {
		SymbolType symType = extSym.getSymbolType();
		String name = extSym.getName();
		Address addr = extSym.getAddress();
		if (symType == SymbolType.FUNCTION && extSym.getObject() instanceof Function extFunc &&
			!extFunc.isThunk()) {
			Function existingFunction = funcMgr.getFunctionAt(addr);
			if (existingFunction == null) {
				existingFunction =
					funcMgr.createFunction(name, addr, new AddressSet(addr), SourceType.IMPORTED);
			}
			else if (!name.equals(existingFunction.getName())) {
				addLabelIfNeeded(name, addr);
			}
			funcSymbolsCopied++;
		}
		else if (symType == SymbolType.LABEL && extSym.getObject() instanceof Data extData) {
			if (Undefined.isUndefined(extData.getDataType()) &&
				DataUtilities.isUndefinedRange(program, addr, addr.add(extData.getLength()))) {
				DataType undefined = Undefined.getUndefinedDataType(extData.getLength());
				DataUtilities.createData(program, addr, undefined, -1,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			addLabelIfNeeded(name, addr);
			dataSymbolsCopied++;
		}
		else {
			symbolsSkipped++;
		}
	}

	private void addLabelIfNeeded(String name, Address addr) throws InvalidInputException {
		for (Symbol sym : symTable.getSymbolsAsIterator(addr)) {
			if (sym.getName().equals(name)) {
				return;
			}
		}
		symTable.createLabel(addr, name, SourceType.IMPORTED);
	}

	private boolean shouldCopyExtSymbol(Symbol extSym) {
		return !extSym.getParentNamespace().isLibrary();
	}

	private boolean isCommonMemblock(MemoryBlock memBlk) {
		return memBlk.isExecute();
	}

	private boolean isSameMemmap() {
		for (MemoryBlock p1MemBlock : program.getMemory().getBlocks()) {
			if (!isCommonMemblock(p1MemBlock)) {
				continue;
			}
			MemoryBlock p2MemBlock =
				externalDebugProgram.getMemory().getBlock(p1MemBlock.getStart());
			if (p2MemBlock == null || !p2MemBlock.getName().equals(p1MemBlock.getName()) ||
				p2MemBlock.getSize() != p1MemBlock.getSize()) {
				return false;
			}
		}
		return true;
	}

}
