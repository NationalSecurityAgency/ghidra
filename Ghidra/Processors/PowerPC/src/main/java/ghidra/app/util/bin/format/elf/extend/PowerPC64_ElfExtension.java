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
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.ElfDynamicType.ElfDynamicValueType;
import ghidra.app.util.bin.format.elf.relocation.PowerPC64_ElfRelocationType;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.address.*;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class PowerPC64_ElfExtension extends ElfExtension {

	private static final int PLT_ENTRY_SIZE = 8; // could be 16(local) or 24 w/ opd_api, 32 for VxWorks
	private static final int PLT_HEAD_SIZE = 16; // could be 24 w/ obd_api, 32 for VxWorks

	// Elf Dynamic Type Extensions
	public static final ElfDynamicType DT_PPC64_GLINK = new ElfDynamicType(0x70000000,
		"DT_PPC64_GLINK", "Specify the start of the .glink section", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_PPC64_OPD = new ElfDynamicType(0x70000001, "DT_PPC64_OPD",
		"Specify the start of the .opd section", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_PPC64_OPDSZ = new ElfDynamicType(0x70000002,
		"DT_PPC64_OPDSZ", "Specify the size of the .opd section", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_PPC64_OPT = new ElfDynamicType(0x70000003, "DT_PPC64_OPT",
		"Specify whether various optimizations are possible", ElfDynamicValueType.VALUE);

	// PPC64 ABI Version Flag Bits contained within ElfHeader e_flags
	private static final int EF_PPC64_ABI = 3;

	// DT_PPC64_OPT bits
	private static final int PPC64_OPT_TLS = 1;
	private static final int PPC64_OPT_MULTI_TOC = 2;
	private static final int PPC64_OPT_LOCALENTRY = 4;

	// ELFv2 ABI symbol st_other bits
	//   STO_PPC64_LOCAL specifies the number of instructions between a
	//   function's global entry point and local entry point
	private static final int STO_PPC64_LOCAL_BIT = 5;
	private static final int STO_PPC64_LOCAL_MASK = 0xE0;

	// Use equate for ELFv1 to remember if function descriptors use 2 or 3 pointers.
	// An equate value of 0 indicates 3-pointers, while 1 indicates 2-pointers
	private static final String FN_DESCR_TYPE_NAME = "_ELFv1_PPC64_FN_DESCR_TYPE_";

	public static final String TOC_BASE = "TOC_BASE"; // injected symbol to mark global TOC_BASE

	public static final String OPD_SECTION_NAME = ".opd";

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_PPC64;
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		Language language = elfLoadHelper.getProgram().getLanguage();
		return canHandle(elfLoadHelper.getElfHeader()) &&
			"PowerPC".equals(language.getProcessor().toString());
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

		if (getPpc64ElfABIVersion(elfLoadHelper.getElfHeader()) != 2) {
			processOPDSection(elfLoadHelper, monitor); // establishes OPD_SIZE equate
		}

		// Super handles conventional GOT and executable PLT 
		super.processGotPlt(elfLoadHelper, monitor);

		// ppc64 extension only handles non-execute PLT containing pointers or function descriptors
		ElfHeader elf = elfLoadHelper.getElfHeader();
		if (getPpc64ElfABIVersion(elf) == 2) {
			setPpc64ELFv2TocBase(elfLoadHelper, monitor);
		}
		if (!processPpc64DynamicPltPointerTable(elfLoadHelper, monitor)) {
			processPpc64PltSectionPointerTable(elfLoadHelper, monitor);
		}
	}

	private void setPpc64ELFv2TocBase(ElfLoadHelper elfLoadHelper, TaskMonitor monitor) {
		// paint TOC_BASE value as r2 across executable blocks since r2
		// is needed to resolve call stubs
		Symbol tocSymbol = SymbolUtilities.getLabelOrFunctionSymbol(elfLoadHelper.getProgram(),
			TOC_BASE, err -> elfLoadHelper.getLog().appendMsg("PowerPC64_ELF", err));
		if (tocSymbol != null) {
			paintTocAsR2value(tocSymbol.getAddress().getOffset(), elfLoadHelper, monitor);
		}
	}

	private void rememberELFv1FunctionDescriptorSize(ElfLoadHelper elfLoadHelper,
			boolean hasThreePointerFnDescriptor) {
		EquateTable equateTable = elfLoadHelper.getProgram().getEquateTable();
		try {
			equateTable.createEquate(FN_DESCR_TYPE_NAME, hasThreePointerFnDescriptor ? 0 : 1);
		}
		catch (DuplicateNameException | InvalidInputException e) {
			Msg.error(this, "Unexpected exception", e);
		}
	}

	/**
	 * Recall the determination of function desciptors using 2 or 3 pointers for ELFv1.
	 * The {@link #rememberELFv1FunctionDescriptorSize(ElfLoadHelper, boolean)} must have been
	 * previously invoked to store this via an Equate use {@link #FN_DESCR_TYPE_NAME}.
	 * @param elfLoadHelper ELF load helper
	 * @return true if 3-pointer or false if 2-pointer function descriptor, null if never stored
	 */
	private Boolean hasELFv1ThreePointerFnDescriptor(ElfLoadHelper elfLoadHelper) {
		EquateTable equateTable = elfLoadHelper.getProgram().getEquateTable();
		Equate value = equateTable.getEquate(FN_DESCR_TYPE_NAME);
		if (value == null) {
			return null;
		}
		return value.getValue() == 0;
	}

	/**
	 * Determine the ELFv1 Function Descriptor size/type by checking TOC_Base entry for first
	 * two .opd entries.
	 * @param opdAddr entry address of within .opd (generally, should be first entry)
	 * @param uses32bitPtr true if 32-bit pointers are used, false if 64-bit
	 * @param mem program memory
	 * @param isFirstEntry true if opdAddr corresponds to first entry
	 * @return true if .opd entried consist of three pointers, false if two pointers
	 * @throws MemoryAccessException if memory access error occurs while checking .opd entries
	 * @throws AddressOverflowException if address error occurs while checking .opd entries
	 */
	private boolean hasELFv1ThreePointerFnDescriptor(Address opdAddr, boolean uses32bitPtr,
			Memory mem, boolean isFirstEntry)
			throws MemoryAccessException, AddressOverflowException {

		// NOTE: This method assumes the first two entries within the .opd region will have the same
		// TOC value (2nd pointer).  I'm sure this is over simplified and could fail for some larger
		// binaries.  If a better test is devised it could replace the use of this method.

		int pointerSize = uses32bitPtr ? 4 : 8;

		long tocValue = getUnsignedValue(opdAddr.addNoWrap(pointerSize), uses32bitPtr, mem);

		// look forward assuming 2-pointer descriptor size
		try {
			long nextTocValue =
				getUnsignedValue(opdAddr.addNoWrap(3 * pointerSize), uses32bitPtr, mem);
			if (nextTocValue == tocValue) {
				return false;
			}

			if (!isFirstEntry) {
				long prevTocValue =
					getUnsignedValue(opdAddr.subtractNoWrap(pointerSize), uses32bitPtr, mem);
				if (prevTocValue == tocValue) {
					return false;
				}
			}
		}
		catch (AddressOverflowException | MemoryAccessException e) {
			// ignore error from peeking around
		}

		return true; // assume 3-pointer descriptor use
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

	private void processPpc64PltSectionPointerTable(ElfLoadHelper elfLoadHelper,
			TaskMonitor monitor) throws CancelledException {

		MemoryBlock pltBlock = getPltSectionBlockSetReadOnly(elfLoadHelper);
		if (pltBlock == null) {
			return; // .plt not found or is executable
		}

		ElfHeader elf = elfLoadHelper.getElfHeader();
		if (getPpc64ElfABIVersion(elf) == 2) {
			markupELFv2PltGot(elfLoadHelper, pltBlock.getStart(), -1, monitor);
		}
		else {
			markupELFv1PltPointerTable(elfLoadHelper, pltBlock.getStart(), -1, monitor);
		}
	}

	private boolean processPpc64DynamicPltPointerTable(ElfLoadHelper elfLoadHelper,
			TaskMonitor monitor) throws CancelledException {

		ElfHeader elf = elfLoadHelper.getElfHeader();

		ElfDynamicTable dynamicTable = elf.getDynamicTable();
		if (dynamicTable == null || !dynamicTable.containsDynamicValue(ElfDynamicType.DT_PLTGOT) ||
			!dynamicTable.containsDynamicValue(ElfDynamicType.DT_PLTRELSZ) ||
			!dynamicTable.containsDynamicValue(ElfDynamicType.DT_PLTREL)) {
			return false;
		}

		try {
			long pltgotOffset =
				elf.adjustAddressForPrelink(dynamicTable.getDynamicValue(ElfDynamicType.DT_PLTGOT));
			Address pltAddr = elfLoadHelper.getDefaultAddress(pltgotOffset);
			Program program = elfLoadHelper.getProgram();
			MemoryBlock block = program.getMemory().getBlock(pltAddr);
			if (block == null || block.isExecute()) {
				return false; // PLT block not found or is executable
			}

			// Compute number of entries in .pltgot based upon number of associated dynamic relocations
			int relEntrySize = (dynamicTable
					.getDynamicValue(ElfDynamicType.DT_PLTREL) == ElfDynamicType.DT_RELA.value) ? 24
							: 16;
			long pltEntryCount =
				dynamicTable.getDynamicValue(ElfDynamicType.DT_PLTRELSZ) / relEntrySize;

			if (getPpc64ElfABIVersion(elf) == 2) {
				markupELFv2PltGot(elfLoadHelper, pltAddr, pltEntryCount, monitor);
			}
			else {
				markupELFv1PltPointerTable(elfLoadHelper, pltAddr, pltEntryCount, monitor);
			}
		}
		catch (NotFoundException e) {
			throw new AssertException("Unexpected Error", e);
		}
		return true;
	}

	private void markupELFv2PltGot(ElfLoadHelper elfLoadHelper, Address pltAddr, long pltEntryCount,
			TaskMonitor monitor) throws CancelledException {

		int pointerSize = elfLoadHelper.getProgram().getDefaultPointerSize();

		if (pltEntryCount <= 0) {
			// compute based upon block size
			MemoryBlock pltBlock = elfLoadHelper.getProgram().getMemory().getBlock(pltAddr);
			pltEntryCount = (pltBlock.getSize() - PLT_HEAD_SIZE) / pointerSize;
		}

		Address addr = pltAddr.add(PLT_HEAD_SIZE);
		try {
			monitor.setShowProgressValue(true);
			monitor.setProgress(0);
			monitor.setMaximum(pltEntryCount);
			int count = 0;

			for (int i = 0; i < pltEntryCount; i++) {
				monitor.checkCancelled();
				monitor.setProgress(++count);
				if (elfLoadHelper.createData(addr, PointerDataType.dataType) == null) {
					break; // stop early if failed to create a pointer
				}
				addr = addr.addNoWrap(pointerSize);
			}
		}
		catch (AddressOverflowException e) {
			// ignore
		}
	}

	private void markupELFv1PltPointerTable(ElfLoadHelper elfLoadHelper, Address pltAddr,
			long pltEntryCount, TaskMonitor monitor) throws CancelledException {

		// Recover ELFv1 function descriptor type from stored Equate
		Boolean hasThreePointerFnDescriptor = hasELFv1ThreePointerFnDescriptor(elfLoadHelper);
		if (hasThreePointerFnDescriptor == null) {
			return;
		}

		// NOTE: There are different conventions for the PLT based upon specific ABI
		//		 conventions.  Dectecting what convention applies can be very tricky
		//		 and may requiring applying some hueristic.  For now we will avoid 
		//		 marking up this section and rely on other analysis.
		//
		// Case observations:
		//       - Shared library for ELFv1 treated .plt section similar to .opd with
		//		 the placement of function descriptors (3 pointers).

		Program program = elfLoadHelper.getProgram();
		Memory mem = program.getMemory();

		int fnDescriptorSize = hasThreePointerFnDescriptor ? 3 : 2;
		int pointerByteSize = program.getDefaultPointerSize();
		int opdEntryByteSize = fnDescriptorSize * pointerByteSize;

		if (pltEntryCount <= 0) {
			// compute based upon block size
			MemoryBlock pltBlock = elfLoadHelper.getProgram().getMemory().getBlock(pltAddr);
			pltEntryCount = pltBlock.getSize() / opdEntryByteSize;
		}

		try {
			monitor.setShowProgressValue(true);
			monitor.setProgress(0);
			monitor.setMaximum(pltEntryCount);
			int count = 0;

			for (int i = 0; i < pltEntryCount; i++) {
				monitor.checkCancelled();
				monitor.setProgress(++count);

				// NOTE: First entry is skipped intentionally
				pltAddr = pltAddr.addNoWrap(opdEntryByteSize);

				Symbol refSymbol = markupDescriptorEntry(pltAddr, false,
					hasThreePointerFnDescriptor, elfLoadHelper);
				if (refSymbol != null && refSymbol.getSymbolType() == SymbolType.FUNCTION &&
					refSymbol.getSource() == SourceType.DEFAULT &&
					!mem.isExternalBlockAddress(refSymbol.getAddress())) {

					// TODO: Rename of DEFAULT thunk should always be avoided (see GP-5872)

					try {
						// Rename default symbol with non-default source to prevent potential removal 
						// by clear-flow. 
						refSymbol.setName(".plt." + refSymbol.getName(), SourceType.IMPORTED);
					}
					catch (DuplicateNameException | InvalidInputException e) {
						// ignore
					}
				}
			}
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

	private MemoryBlock getPltSectionBlockSetReadOnly(ElfLoadHelper elfLoadHelper) {

		ElfHeader elf = elfLoadHelper.getElfHeader();
		ElfSectionHeader pltSection = elf.getSection(ElfSectionHeaderConstants.dot_plt);
		if (pltSection == null) {
			return null;
		}
		Program program = elfLoadHelper.getProgram();
		MemoryBlock pltBlock = program.getMemory().getBlock(pltSection.getNameAsString());
		if (pltBlock == null) {
			return null;
		}
		if (pltSection.isExecutable()) {
			return null;
		}

		// set pltBlock read-only to permit decompiler simplification
		pltBlock.setWrite(false);

		return pltBlock;
	}

	private void processOPDSection(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {

		boolean makeSymbol = false;
		Program program = elfLoadHelper.getProgram();
		Memory mem = program.getMemory();
		MemoryBlock opdBlock = mem.getBlock(OPD_SECTION_NAME);
		if (opdBlock == null) {

			// Handle case where section names have been stripped - find .opd section
			ElfHeader elf = elfLoadHelper.getElfHeader();
			if (elf.getSectionHeaderCount() == 0 || !(elf.isExecutable() || elf.isSharedObject())) {
				return;
			}

			// Determine entry address which should point into .opd block
			long entry = elf.e_entry();
			if (entry == 0) {
				return;
			}
			AddressFactory addrFactory = program.getAddressFactory();
			entry += elfLoadHelper.getImageBaseWordAdjustmentOffset();
			Address entryAddress =
				addrFactory.getDefaultAddressSpace().getTruncatedAddress(entry, true);
			opdBlock = mem.getBlock(entryAddress);
			makeSymbol = true;
		}

		if (opdBlock == null || !opdBlock.isInitialized() || opdBlock.isExecute()) {
			return;
		}

		if (makeSymbol) {
			try {
				// Create .opd symbol if section lacked this name
				elfLoadHelper.createSymbol(opdBlock.getStart(), OPD_SECTION_NAME, false, false,
					null);
			}
			catch (InvalidInputException e) {
				// ignore - unexpected
			}
		}

		monitor.setMessage("Processing Function Descriptor Symbols...");

		Address addr = opdBlock.getStart();
		Address endAddr = opdBlock.getEnd();

		try {
			int pointerByteSize = program.getDefaultPointerSize();
			boolean hasThreePointerFnDescriptor =
				hasELFv1ThreePointerFnDescriptor(addr, pointerByteSize == 4, mem, true);
			int fnDescriptorSize = hasThreePointerFnDescriptor ? 3 : 2;
			int opdEntryByteSize = fnDescriptorSize * pointerByteSize;

			rememberELFv1FunctionDescriptorSize(elfLoadHelper, hasThreePointerFnDescriptor); // remember as equate

			monitor.setShowProgressValue(true);
			monitor.setProgress(0);
			monitor.setMaximum((endAddr.subtract(addr) + 1) / opdEntryByteSize);
			int count = 0;

			while (addr.compareTo(endAddr) < 0) {
				monitor.checkCancelled();
				monitor.setProgress(++count);
				processOPDEntry(elfLoadHelper, addr, hasThreePointerFnDescriptor);
				addr = addr.addNoWrap(opdEntryByteSize);
			}
		}
		catch (MemoryAccessException | AddressOverflowException e) {
			// ignore end of space or failure to detect descriptor size
		}

		// allow .opd section contents to be treated as constant values
		opdBlock.setWrite(false);
	}

	private long getUnsignedValue(Address addr, boolean uses32bitPtr, Memory mem)
			throws MemoryAccessException {
		return uses32bitPtr ? Integer.toUnsignedLong(mem.getInt(addr)) : mem.getLong(addr);
	}

	private void processOPDEntry(ElfLoadHelper elfLoadHelper, Address opdAddr,
			boolean fnDescriptorHasEnvPtr) {

		Program program = elfLoadHelper.getProgram();
		SymbolTable symbolTable = program.getSymbolTable();

		boolean isGlobal = symbolTable.isExternalEntryPoint(opdAddr);

		Symbol refSymbol =
			markupDescriptorEntry(opdAddr, isGlobal, fnDescriptorHasEnvPtr, elfLoadHelper);
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
					refSymbol.setName(OPD_SECTION_NAME + "." + refSymbol.getName(),
						SourceType.IMPORTED);
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
			boolean hasThreePointerFnDescriptor, ElfLoadHelper elfLoadHelper) {
		Program program = elfLoadHelper.getProgram();

		// markup function descriptor (two or three pointers)
		Data refPtr = elfLoadHelper.createData(entryAddr, PointerDataType.dataType); // function *
		Data tocPtr = elfLoadHelper.createData(entryAddr.add(program.getDefaultPointerSize()),
			PointerDataType.dataType); // toc *

		if (refPtr == null || tocPtr == null) {
			Msg.error(this, "Failed to process PPC64 function descriptor at " + entryAddr);
			return null;
		}

		// FIXME! How do we determine if an env* is present - descriptor may only have two pointers
		// instead of three.

		if (hasThreePointerFnDescriptor) {
			elfLoadHelper.createData(entryAddr.add(2 * program.getDefaultPointerSize()),
				PointerDataType.dataType); // env *
		}

		Address refAddr = (Address) refPtr.getValue();
		if (refAddr == null || refAddr.getOffset() == 0 ||
			program.getMemory().getBlock(refAddr) == null) {
			return null;
		}

		Address tocAddr = (Address) tocPtr.getValue();
		if (tocAddr == null || tocAddr.getOffset() == 0) {
			return null;
		}

		ElfDefaultGotPltMarkup.setConstant(refPtr);
		ElfDefaultGotPltMarkup.setConstant(tocPtr);

		Function function = program.getListing().getFunctionAt(refAddr);
		if (function == null) {
			// Check for potential pointer table (unsure a non-function would be referenced by OPD section)
			List<Relocation> relocations = program.getRelocationTable().getRelocations(refAddr);
			if (!relocations.isEmpty() && relocations.get(0)
					.getType() == PowerPC64_ElfRelocationType.R_PPC64_RELATIVE.typeId) {
				return program.getSymbolTable().getPrimarySymbol(refAddr);
			}

			// Otherwise, create function at OPD referenced location
			function = elfLoadHelper.createOneByteFunction(null, refAddr, isGlobal);
		}

		// set r2 to TOC base for each function
		Register r2reg = program.getRegister("r2");
		RegisterValue tocValue = new RegisterValue(r2reg, tocAddr.getOffsetAsBigInteger());
		try {
			program.getProgramContext().setRegisterValue(refAddr, refAddr, tocValue);
		}
		catch (ContextChangeException e) {
			throw new AssertException(e);
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

		if (getPpc64ElfABIVersion(elfLoadHelper.getElfHeader()) == 2) {

			monitor.setMessage("Assuming r12 for global functions...");

			FunctionManager functionMgr = program.getFunctionManager();
			for (Address addr : program.getSymbolTable().getExternalEntryPointIterator()) {
				monitor.checkCancelled();
				if (functionMgr.getFunctionAt(addr) != null) {
					// assume r12 set to function entry for all global functions
					setPPC64v2GlobalFunctionR12Context(program, addr);
				}
			}

			// ensure that r12 context has been set on global entry function
			Symbol entrySymbol = SymbolUtilities.getLabelOrFunctionSymbol(
				elfLoadHelper.getProgram(), ElfLoader.ELF_ENTRY_FUNCTION_NAME,
				err -> elfLoadHelper.getLog().appendMsg("PowerPC64_ELF", err));
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
			getPpc64ElfABIVersion(elfHeader) != 2) {
			return address;
		}

		// NOTE: I don't think the ELFv1 ABI supports little-endian
		Language language = elfLoadHelper.getProgram().getLanguage();
		if (!canHandle(elfLoadHelper) || elfHeader.e_machine() != ElfConstants.EM_PPC64 ||
			language.getLanguageDescription().getSize() != 64) {
			return address;
		}

		// Handle V2 ABI - st_other signals local entry vs. global entry behavior and offset.
		// 4-byte instructions are assumed.l

		String name = elfSymbol.getNameAsString();
		Function localFunction = null;

		int localOffset = PPC64_ABIV2_GLOBAL_ENTRY_OFFSET[(elfSymbol.getOther() & 0xe0) >>> 5] * 4;
		if (localOffset != 0) {
			// generate local function 			
			String localName = "";
			if (!StringUtils.isBlank(name)) {
				// NOTE: this naming could cause issues with mangled name use
				localName = "." + name;
			}
			try {
				Address localFunctionAddr = address.add(localOffset);
				localFunction =
					elfLoadHelper.createOneByteFunction(localName, localFunctionAddr, false);

				// TODO: global function should be a thunk to the local function - need analyzer to do this
				String cmt = "local function entry for global function " + name + " at {@address " +
					address + "}";
				elfLoadHelper.getProgram()
						.getListing()
						.setComment(localFunctionAddr, CommentType.PRE, cmt);
			}
			catch (Exception e) {
				elfLoadHelper.log("Failed to generate local function symbol " + localName + " at " +
					address + "+" + localOffset);
			}
		}

		Function f = elfLoadHelper.createOneByteFunction(name, address, false);
		if (f != null && localFunction != null) {
			f.setThunkedFunction(localFunction);
			elfLoadHelper.setElfSymbolAddress(elfSymbol, address);
			return null; // symbol creation handled
		}

		return address;
	}

	/**
	 * Get the PPC64 ELF ABI version specified within the ELF header.
	 * Expected values include:
	 * <ul>
	 * <li> 1 for original function descriptor use (i.e., .opd) </li>
	 * <li> 2 for revised ABI without function descriptors </li>
	 * <li> 0 for unspecified or not using any features affected by the differences (ELFv1 assumed)</li>
	 * </ul>
	 * @param elf ELF header
	 * @return ELF ABI version
	 */
	public static int getPpc64ElfABIVersion(ElfHeader elf) {
		if (elf.e_machine() != ElfConstants.EM_PPC64) {
			return 0;
		}

		if (elf.getSection(OPD_SECTION_NAME) != null) {
			return 1;
		}

		// TODO: While the e_flags should indicate the use of function descriptors, this
		// may not be set reliably.  The presence of the .opd section is another
		// indicator but could be missing if sections have been stripped.
		return elf.e_flags() & EF_PPC64_ABI;
	}

}
