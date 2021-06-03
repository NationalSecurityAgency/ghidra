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
package ghidra.app.util.bin.format.elf.extend;

import java.math.BigInteger;

import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.ElfDynamicType.ElfDynamicValueType;
import ghidra.app.util.bin.format.elf.relocation.PowerPC64_ElfRelocationConstants;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.address.*;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class PowerPC64_ElfExtension extends ElfExtension {

	// Elf Dynamic Type Extensions
	public static final ElfDynamicType DT_PPC64_GLINK = new ElfDynamicType(0x70000000,
		"DT_PPC64_GLINK", "Specify the start of the .glink section", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_PPC64_OPD = new ElfDynamicType(0x70000001, "DT_PPC64_OPD",
		"Specify the start of the .opd section", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_PPC64_OPDSZ = new ElfDynamicType(0x70000002,
		"DT_PPC64_OPDSZ", "Specify the size of the .opd section", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_PPC64_OPT = new ElfDynamicType(0x70000003, "DT_PPC64_OPT",
		"Specify whether various optimisations are possible", ElfDynamicValueType.VALUE);

	// PPC64 ABI Version Flag Bits contained within ElfHeader e_flags
	private static final int EF_PPC64_ABI = 3;

	public static final String TOC_BASE = "TOC_BASE"; // injected symbol to mark global TOC_BASE

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_PPC64 && elf.is64Bit();
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		Language language = elfLoadHelper.getProgram().getLanguage();
		return canHandle(elfLoadHelper.getElfHeader()) &&
			"PowerPC".equals(language.getProcessor().toString()) &&
			language.getLanguageDescription().getSize() == 64;
	}

	@Override
	public String getDataTypeSuffix() {
		return "_PPC64";
	}

	@Override
	public void processElf(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {

		if (!canHandle(elfLoadHelper)) {
			return;
		}

		findTocBase(elfLoadHelper, monitor); // create TOC_BASE symbol (used by relocations)
	}

	@Override
	public void processGotPlt(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {

		if (!canHandle(elfLoadHelper)) {
			return;
		}

		setEntryPointContext(elfLoadHelper, monitor);

		processOPDSection(elfLoadHelper, monitor);

		super.processGotPlt(elfLoadHelper, monitor);

		processPpc64v2PltPointerTable(elfLoadHelper, monitor);
		processPpc64PltGotPointerTable(elfLoadHelper, monitor);
	}

	private void findTocBase(ElfLoadHelper elfLoadHelper, TaskMonitor monitor) {

		// TODO: Verify that this works for non-V2 ABI cases (this assumes TOC based upon .got location)

		Program program = elfLoadHelper.getProgram();

		try {
			Address tocAddr = null;

			// Check for .toc section
			MemoryBlock tocBlock = program.getMemory().getBlock(".toc");
			if (tocBlock != null) {
				tocAddr = tocBlock.getStart();
			}
			else {
				MemoryBlock gotBlock =
					program.getMemory().getBlock(ElfSectionHeaderConstants.dot_got);
				if (gotBlock != null) {
					tocAddr = gotBlock.getStart().addNoWrap(0x8000);
				}
			}

			if (tocAddr != null) {
				elfLoadHelper.createSymbol(tocAddr, TOC_BASE, false, false, null);
			}

		}
		catch (AddressOverflowException | InvalidInputException e) {
			// ignore
		}
	}

	private void processPpc64PltGotPointerTable(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {

		ElfHeader elf = elfLoadHelper.getElfHeader();
		if (getPpc64ABIVersion(elf) == 2) {
			// paint TOC_BASE value as r2 across executable blocks since r2
			// is needed to resolve call stubs
			Symbol tocSymbol = SymbolUtilities.getLabelOrFunctionSymbol(elfLoadHelper.getProgram(),
				TOC_BASE, err -> elfLoadHelper.getLog().error("PowerPC64_ELF", err));
			if (tocSymbol != null) {
				paintTocAsR2value(tocSymbol.getAddress().getOffset(), elfLoadHelper, monitor);
			}
			// TODO: verify ABI detection
			return;
		}

		ElfDynamicTable dynamicTable = elf.getDynamicTable();
		if (dynamicTable == null || !dynamicTable.containsDynamicValue(ElfDynamicType.DT_PLTGOT) ||
			!dynamicTable.containsDynamicValue(ElfDynamicType.DT_PLTRELSZ) ||
			!dynamicTable.containsDynamicValue(ElfDynamicType.DT_PLTREL)) {
			return;
		}

		try {
			long pltgotOffset =
				elf.adjustAddressForPrelink(dynamicTable.getDynamicValue(ElfDynamicType.DT_PLTGOT));
			Address pltAddr = elfLoadHelper.getDefaultAddress(pltgotOffset);
			Program program = elfLoadHelper.getProgram();
			MemoryBlock pltBlock = program.getMemory().getBlock(pltAddr);
			if (pltBlock == null || pltBlock.isExecute()) {
				return;
			}

			int relEntrySize = (dynamicTable.getDynamicValue(
				ElfDynamicType.DT_PLTREL) == ElfDynamicType.DT_RELA.value) ? 24 : 16;

			long pltEntryCount =
				dynamicTable.getDynamicValue(ElfDynamicType.DT_PLTRELSZ) / relEntrySize;

			for (int i = 0; i < pltEntryCount; i++) {
				monitor.checkCanceled();
				pltAddr = pltAddr.addNoWrap(24);
				Symbol refSymbol = markupDescriptorEntry(pltAddr, false, elfLoadHelper);
				if (refSymbol != null && refSymbol.getSymbolType() == SymbolType.FUNCTION &&
					refSymbol.getSource() == SourceType.DEFAULT) {
					try {
						// Force source type on function to prevent potential removal by clear-flow
						refSymbol.setName(".pltgot." + refSymbol.getName(), SourceType.IMPORTED);
					}
					catch (DuplicateNameException | InvalidInputException e) {
						// ignore
					}
				}
			}
		}
		catch (NotFoundException e) {
			throw new AssertException("unexpected", e);
		}
		catch (AddressOverflowException e) {
			elfLoadHelper.log("Failed to process PltGot entries: " + e.getMessage());
		}
	}

	private void paintTocAsR2value(long tocBaseOffset, ElfLoadHelper elfLoadHelper,
			TaskMonitor monitor) {

		Program program = elfLoadHelper.getProgram();
		ProgramContext programContext = program.getProgramContext();
		Register r2reg = program.getRegister("r2");
		RegisterValue tocValue = new RegisterValue(r2reg, BigInteger.valueOf(tocBaseOffset));

		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (block.isExecute()) {
				try {
					programContext.setRegisterValue(block.getStart(), block.getEnd(), tocValue);
				}
				catch (ContextChangeException e) {
					String msg = "Failed to set r2 as TOC_BASE on memory block " + block.getName();
					Msg.error(this, msg + ": " + e.getMessage());
					elfLoadHelper.log(msg);
				}
			}
		}

	}

	private void processPpc64v2PltPointerTable(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {

		ElfHeader elf = elfLoadHelper.getElfHeader();
		ElfSectionHeader pltSection = elf.getSection(ElfSectionHeaderConstants.dot_plt);
		if (pltSection == null) {
			return;
		}
		Program program = elfLoadHelper.getProgram();
		MemoryBlock pltBlock = program.getMemory().getBlock(pltSection.getNameAsString());
		// TODO: This is a band-aid since there are many PLT implementations and this assumes only one.
		if (pltBlock == null || pltBlock.getSize() <= ElfConstants.PLT_ENTRY_SIZE) {
			return;
		}
		if (pltSection.isExecutable()) {
			return;
		}

		// set pltBlock read-only to permit decompiler simplification
		pltBlock.setWrite(false);

		if (getPpc64ABIVersion(elf) != 2) {
			// TODO: add support for other PLT implementations
			return;
		}

		// TODO: Uncertain

		Address addr = pltBlock.getStart().add(ElfConstants.PLT_ENTRY_SIZE);
		try {
			while (addr.compareTo(pltBlock.getEnd()) < 0) {
				monitor.checkCanceled();
				if (elfLoadHelper.createData(addr, PointerDataType.dataType) == null) {
					break; // stop early if failed to create a pointer
				}
				addr = addr.addNoWrap(8);
			}
		}
		catch (AddressOverflowException e) {
			// ignore
		}

	}

	private void processOPDSection(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {

		MemoryBlock opdBlock = elfLoadHelper.getProgram().getMemory().getBlock(".opd");
		if (opdBlock == null) {
			return;
		}

		monitor.setMessage("Processing Function Descriptor Symbols...");

		Address addr = opdBlock.getStart();
		Address endAddr = opdBlock.getEnd();

		monitor.setShowProgressValue(true);
		monitor.setProgress(0);
		monitor.setMaximum((endAddr.subtract(addr) + 1) / 24);
		int count = 0;

		try {
			while (addr.compareTo(endAddr) < 0) {
				monitor.checkCanceled();
				monitor.setProgress(++count);
				processOPDEntry(elfLoadHelper, addr);
				addr = addr.addNoWrap(24);
			}
		}
		catch (AddressOverflowException e) {
			// ignore end of space
		}

		// allow .opd section contents to be treated as constant values
		opdBlock.setWrite(false);
	}

	private void processOPDEntry(ElfLoadHelper elfLoadHelper, Address opdAddr) {

		Program program = elfLoadHelper.getProgram();
		SymbolTable symbolTable = program.getSymbolTable();

		boolean isGlobal = symbolTable.isExternalEntryPoint(opdAddr);

		Symbol refSymbol = markupDescriptorEntry(opdAddr, isGlobal, elfLoadHelper);
		if (refSymbol == null) {
			return;
		}
		Address refAddr = refSymbol.getAddress();

		// Remove OPD function if one was created - a function symbol in the
		// OPD section should not be a function as it is a descriptor entry only.
		Function f = program.getFunctionManager().getFunctionAt(opdAddr);
		if (f == null) {
			// no OPD function symbol - rename referenced Function to non-default name to
			// help preserve it if it gets in the path of a future clear-flow command.
			if (refSymbol.getSymbolType() == SymbolType.FUNCTION &&
				refSymbol.getSource() == SourceType.DEFAULT) {
				try {
					// Force source type on function to prevent potential removal by clear-flow
					refSymbol.setName(".opd." + refSymbol.getName(), SourceType.IMPORTED);
				}
				catch (DuplicateNameException | InvalidInputException e) {
					// ignore
				}
			}
			return; // assume it was already handled
		}
		// eliminate function on descriptor
		f.getSymbol().delete();

		// TODO: Could we have problems by moving the symbol from the descriptor
		// table to the actual function?

		Symbol[] symbols = program.getSymbolTable().getSymbols(opdAddr);
		for (Symbol symbol : symbols) {
			if (symbol.isDynamic()) {
				continue;
			}
			String name = symbol.getName(); // primary should be first
			symbol.delete();
			try {
				elfLoadHelper.createSymbol(refAddr, name, false, false, null);
			}
			catch (InvalidInputException e) {
				Msg.error(this, "Failed to move function descriptor symbol properly: " + name);
			}
		}
	}

	private Symbol markupDescriptorEntry(Address entryAddr, boolean isGlobal,
			ElfLoadHelper elfLoadHelper) {
		Program program = elfLoadHelper.getProgram();

		// markup function descriptor (3 elements, 24-bytes)
		Data refPtr = elfLoadHelper.createData(entryAddr, PointerDataType.dataType);
		Data tocPtr = elfLoadHelper.createData(entryAddr.add(program.getDefaultPointerSize()),
			PointerDataType.dataType);
		// TODO: uncertain what 3rd procedure descriptor element represents
		elfLoadHelper.createData(entryAddr.add(2 * program.getDefaultPointerSize()),
			QWordDataType.dataType);

		if (refPtr == null || tocPtr == null) {
			Msg.error(this, "Failed to process PPC64 descriptor at " + entryAddr);
			return null;
		}

		Address refAddr = (Address) refPtr.getValue();
		if (refAddr == null || program.getMemory().getBlock(refAddr) == null) {
			return null;
		}

		ElfDefaultGotPltMarkup.setConstant(refPtr);
		ElfDefaultGotPltMarkup.setConstant(tocPtr);

		Function function = program.getListing().getFunctionAt(refAddr);
		if (function == null) {
			// Check for potential pointer table (unsure a non-function would be referenced by OPD section)
			Relocation reloc = program.getRelocationTable().getRelocation(refAddr);
			if (reloc != null &&
				reloc.getType() == PowerPC64_ElfRelocationConstants.R_PPC64_RELATIVE) {
				return program.getSymbolTable().getPrimarySymbol(refAddr);
			}

			// Otherwise, create function at OPD referenced location
			function = elfLoadHelper.createOneByteFunction(null, refAddr, isGlobal);
		}

		// set r2 to TOC base for each function
		Address tocAddr = (Address) tocPtr.getValue();
		if (tocAddr != null) {
			Register r2reg = program.getRegister("r2");
			RegisterValue tocValue = new RegisterValue(r2reg, tocAddr.getOffsetAsBigInteger());
			try {
				program.getProgramContext().setRegisterValue(refAddr, refAddr, tocValue);
			}
			catch (ContextChangeException e) {
				throw new AssertException(e);
			}
		}
		return function.getSymbol();
	}

	private void setPPC64v2GlobalFunctionR12Context(Program program, Address functionAddr) {
		// Global entry - assume r12 contains function address
		RegisterValue entryOffset = new RegisterValue(program.getRegister("r12"),
			BigInteger.valueOf(functionAddr.getOffset()));
		ProgramContext programContext = program.getProgramContext();
		try {
			programContext.setRegisterValue(functionAddr, functionAddr, entryOffset);
		}
		catch (ContextChangeException e) {
			throw new AssertException(e);
		}
	}

	/**
	 * Adjust any program context needed on symbols
	 * @param elfLoadHelper
	 * @param monitor
	 * @throws CancelledException
	 */
	private void setEntryPointContext(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {
		Program program = elfLoadHelper.getProgram();

		if (getPpc64ABIVersion(elfLoadHelper.getElfHeader()) == 2) {

			monitor.setMessage("Assuming r12 for global functions...");

			FunctionManager functionMgr = program.getFunctionManager();
			for (Address addr : program.getSymbolTable().getExternalEntryPointIterator()) {
				monitor.checkCanceled();
				if (functionMgr.getFunctionAt(addr) != null) {
					// assume r12 set to function entry for all global functions
					setPPC64v2GlobalFunctionR12Context(program, addr);
				}
			}

			// ensure that r12 context has been set on global entry function
			Symbol entrySymbol = SymbolUtilities.getLabelOrFunctionSymbol(
				elfLoadHelper.getProgram(), ElfLoader.ELF_ENTRY_FUNCTION_NAME,
				err -> elfLoadHelper.getLog().error("PowerPC64_ELF", err));
			if (entrySymbol != null && entrySymbol.getSymbolType() == SymbolType.FUNCTION) {
				setPPC64v2GlobalFunctionR12Context(program, entrySymbol.getAddress());
			}
		}
	}

	// upper 3-bits of ElfSymbol st_other identify local vs. global behavior and number of instructions
	// at which the local function entry is offset from the global entry.  Local function
	// entry names will be prefixed with a '.'
	private static int[] PPC64_ABIV2_GLOBAL_ENTRY_OFFSET = new int[] { 0, 0, 1, 2, 4, 8, 16, 0 };

	@Override
	public Address evaluateElfSymbol(ElfLoadHelper elfLoadHelper, ElfSymbol elfSymbol,
			Address address, boolean isExternal) {

		ElfHeader elfHeader = elfLoadHelper.getElfHeader();

		// Check for V2 ABI
		if (isExternal || elfSymbol.getType() != ElfSymbol.STT_FUNC ||
			getPpc64ABIVersion(elfHeader) != 2) {
			return address;
		}

		// NOTE: I don't think the ABI supports little-endian
		Language language = elfLoadHelper.getProgram().getLanguage();
		if (!canHandle(elfLoadHelper) || elfHeader.e_machine() != ElfConstants.EM_PPC64 ||
			language.getLanguageDescription().getSize() != 64) {
			return address;
		}

		// Handle V2 ABI - st_other signals local entry vs. global entry behavior and offset.
		// 4-byte instructions are assumed.l

		Function localFunction = null;
		int localOffset = PPC64_ABIV2_GLOBAL_ENTRY_OFFSET[(elfSymbol.getOther() & 0xe0) >>> 5] * 4;
		if (localOffset != 0) {

			// generate local symbol TODO: this should really be done after demangling
			String name = elfSymbol.getNameAsString();
			String localName = "." + name;
			try {
				Address localFunctionAddr = address.add(localOffset);
				localFunction = elfLoadHelper.createOneByteFunction(null, localFunctionAddr, false);
				if (localFunction != null &&
					localFunction.getSymbol().getSource() == SourceType.DEFAULT) {
					elfLoadHelper.createSymbol(localFunctionAddr, localName, true, false, null);
				}
				// TODO: global function should be a thunk to the local function - need analyzer to do this
				String cmt = "local function entry for global function " + name + " at {@address " +
					address + "}";
				elfLoadHelper.getProgram().getListing().setComment(localFunctionAddr,
					CodeUnit.PRE_COMMENT, cmt);
			}
			catch (AddressOutOfBoundsException | InvalidInputException e) {
				elfLoadHelper.log("Failed to generate local function symbol " + localName + " at " +
					address + "+" + localOffset);
			}
		}

		Function f =
			elfLoadHelper.createOneByteFunction(elfSymbol.getNameAsString(), address, false);
		if (f != null && localFunction != null) {
			f.setThunkedFunction(localFunction);
			return null; // symbol creation handled
		}

		return address;
	}

	/**
	 * Get the PPC64 ABI version specified within the ELF header.
	 * Expected values include:
	 * <ul>
	 * <li> 1 for original function descriptor using ABI </li>
	 * <li> 2 for revised ABI without function descriptors </li>
	 * <li> 0 for unspecified or not using any features affected by the differences </li>
	 * </ul>
	 * @param elf ELF header
	 * @return ABI version
	 */
	public static int getPpc64ABIVersion(ElfHeader elf) {
		if (elf.e_machine() != ElfConstants.EM_PPC64) {
			return 0;
		}
		// TODO: While the e_flags should indicate the use of function descriptors, this
		// may not be set reliably.  The presence of the .opd section is another
		// indicator but could be missing if sections have been stripped.
		return elf.e_flags() & EF_PPC64_ABI;
	}

}
