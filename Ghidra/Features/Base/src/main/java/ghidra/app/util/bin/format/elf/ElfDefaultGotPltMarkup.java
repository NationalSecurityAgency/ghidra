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
package ghidra.app.util.bin.format.elf;

import ghidra.app.cmd.refs.RemoveReferenceCmd;
import ghidra.framework.store.LockException;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * <code>ElfDefaultGotPltMarkup</code> provides the legacy/default implementation of ELF GOT/PLT processing 
 * which handles a limited set of cases.  It is intended that over time this default implementation be 
 * eliminated although it may form the basis of an abstract implementation for specific processor
 * extensions.
 */
public class ElfDefaultGotPltMarkup {

	private ElfLoadHelper elfLoadHelper;
	private ElfHeader elf;
	private Program program;
	private Listing listing;
	private Memory memory;

	public ElfDefaultGotPltMarkup(ElfLoadHelper elfLoadHelper) {
		this.elfLoadHelper = elfLoadHelper;
		elf = elfLoadHelper.getElfHeader();
		program = elfLoadHelper.getProgram();
		listing = program.getListing();
		memory = program.getMemory();
	}

	private void log(String msg) {
		elfLoadHelper.log(msg);
	}

	public void process(TaskMonitor monitor) throws CancelledException {
		if (elf.e_shnum() == 0) {
			processDynamicPLTGOT(monitor);
		}
		else {
			processGOTSections(monitor);
			processPLTSection(monitor);
		}
	}

	/**
	 * Process all GOT sections based upon blocks whose names begin with .got
	 * @param monitor task monitor
	 * @throws CancelledException thrown if task cancelled
	 */
	private void processGOTSections(TaskMonitor monitor) throws CancelledException {
		// look for .got section blocks
		MemoryBlock[] blocks = memory.getBlocks();
		for (MemoryBlock gotBlock : blocks) {
			monitor.checkCanceled();

			if (!gotBlock.getName().startsWith(ElfSectionHeaderConstants.dot_got)) {
				continue;
			}
			// Assume the .got section is read_only.  This is not true, but it helps with analysis
			gotBlock.setWrite(false);

			processGOT(gotBlock.getStart(), gotBlock.getEnd(), monitor);
		}
	}

	/**
	 * Process GOT table specified by Dynamic Program Header (DT_PLTGOT).
	 * Entry count determined by corresponding relocation table identified by
	 * the dynamic table entry DT_JMPREL.
	 * @param monitor task monitor
	 * @throws CancelledException thrown if task cancelled
	 */
	private void processDynamicPLTGOT(TaskMonitor monitor) throws CancelledException {

		ElfDynamicTable dynamicTable = elf.getDynamicTable();
		if (dynamicTable == null || !dynamicTable.containsDynamicValue(ElfDynamicType.DT_PLTGOT) ||
			!dynamicTable.containsDynamicValue(ElfDynamicType.DT_JMPREL)) {
			return;
		}

		// NOTE: there may be other relocation table affecting the GOT 
		// corresponding to DT_PLTGOT

		AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
		long imageBaseAdj = elfLoadHelper.getImageBaseWordAdjustmentOffset();

		try {
			long relocTableAddr =
				elf.adjustAddressForPrelink(dynamicTable.getDynamicValue(ElfDynamicType.DT_JMPREL));

			ElfProgramHeader relocTableLoadHeader =
				elf.getProgramLoadHeaderContaining(relocTableAddr);
			if (relocTableLoadHeader == null || relocTableLoadHeader.getOffset() < 0) {
				return;
			}
			long relocTableOffset = relocTableLoadHeader.getOffset(relocTableAddr);
			ElfRelocationTable relocationTable = elf.getRelocationTableAtOffset(relocTableOffset);
			if (relocationTable == null) {
				return;
			}

			// External dynamic symbol entries in the PLTGOT, if any, will be placed
			// after any local symbol entries.

			// While DT_PLTGOT identifies the start of the PLTGOT it does not
			// specify its length.  If there are dynamic non-local entries in the 
			// PLTGOT they should have relocation entries in the table identified 
			// by DT_JMPREL.  It is important to note that this relocation table
			// can include entries which affect other processor-specific PLTGOT
			// tables (e.g., MIPS_PLTGOT) so we must attempt to isolate the 
			// entries which correspond to DT_PLTGOT.  

			// WARNING: This implementation makes a potentially bad assumption that 
			// the last relocation entry will identify the endof the PLTGOT if its
			// offset is beyond the start of the PLTGOT.  This assumption could
			// easily be violated by a processor-specific PLTGOT which falls after
			// the standard PLTGOT in memory and shares the same relocation table.

			long pltgot = elf.adjustAddressForPrelink(
				dynamicTable.getDynamicValue(ElfDynamicType.DT_PLTGOT));

			ElfRelocation[] relocations = relocationTable.getRelocations();

			long lastGotOffset = relocations[relocations.length - 1].getOffset();
			if (lastGotOffset < pltgot) {
				return;
			}

			Address gotStart = defaultSpace.getAddress(pltgot + imageBaseAdj);
			Address gotEnd = defaultSpace.getAddress(lastGotOffset + imageBaseAdj);

			processGOT(gotStart, gotEnd, monitor);
			processDynamicPLT(gotStart, gotEnd, monitor);
		}
		catch (NotFoundException e) {
			throw new AssertException(e);
		}
		catch (AddressOutOfBoundsException e) {
			log("Failed to process GOT: " + e.getMessage());
		}
	}

	/**
	 * Mark-up all GOT entries as pointers within the memory range gotStart to
	 * gotEnd.
	 * @param gotStart address for start of GOT
	 * @param gotEnd address for end of GOT
	 * @param monitor task monitor
	 * @throws CancelledException thrown if task cancelled
	 */
	private void processGOT(Address gotStart, Address gotEnd, TaskMonitor monitor)
			throws CancelledException {

		boolean imageBaseAlreadySet = elf.isPreLinked();

		try {
			Address newImageBase = null;
			while (gotStart.compareTo(gotEnd) <= 0) {
				monitor.checkCanceled();

				Data data = createPointer(gotStart, true);
				if (data == null) {
					break;
				}

				try {
					gotStart = data.getMaxAddress().add(1);
				}
				catch (AddressOutOfBoundsException e) {
					break; // no more room
				}
				newImageBase = UglyImageBaseCheck(data, newImageBase);
			}
			if (newImageBase != null) {
				log("Invalid Address found in .got table.  Suspect Prelinked shared object file");
				if (imageBaseAlreadySet) {
					log("ERROR: Unable to adjust image base for pre-link - retaining existing image base of " +
						program.getImageBase());
				}
				else {
					program.setImageBase(newImageBase, true);
					log("Setting Image base to: " + newImageBase);
					imageBaseAlreadySet = true;
				}
			}
		}
		catch (CodeUnitInsertionException e) {
			log("Failed to process GOT: " + e.getMessage());
		}
		catch (AddressOverflowException e) {
			log("Failed to adjust image base: " + e.getMessage());
		}
		catch (LockException e) {
			throw new AssertException(e);
		}
	}

	private void processPLTSection(TaskMonitor monitor) throws CancelledException {

		// TODO: Handle case where PLT is non-executable pointer table

		if (elf.isRelocatable()) {
			return; //relocatable files do not have .PLT sections
		}

		MemoryBlock pltBlock = memory.getBlock(ElfSectionHeaderConstants.dot_plt);
		// TODO: This is a band-aid since there are many PLT implementations and this assumes only one.
		if (pltBlock == null || !pltBlock.isExecute() ||
			pltBlock.getSize() <= ElfConstants.PLT_ENTRY_SIZE) {
			return;
		}

		int skipPointers = ElfConstants.PLT_ENTRY_SIZE;

		// ARM, AARCH64 and others may not store pointers at start of .plt
		if (elf.e_machine() == ElfConstants.EM_ARM || elf.e_machine() == ElfConstants.EM_AARCH64) {
			// TODO: Should be handled by extension
			skipPointers = 0;
		}

		// Process PLT section
		Address minAddress = pltBlock.getStart().add(skipPointers);
		Address maxAddress = pltBlock.getEnd();
		processLinkageTable(ElfSectionHeaderConstants.dot_plt, minAddress, maxAddress, monitor);
	}

	private void processDynamicPLT(Address gotStart, Address gotEnd, TaskMonitor monitor)
			throws CancelledException {

		Address pltStart = null;
		Address pltEnd = null;

		for (Data gotPtr : listing.getDefinedData(new AddressSet(gotStart.next(), gotEnd), true)) {
			monitor.checkCanceled();
			if (!gotPtr.isPointer()) {
				Msg.error(this, "ELF PLTGOT contains non-pointer");
				return; // unexpected
			}
			Address ptr = (Address) gotPtr.getValue();
			if (ptr.getOffset() == 0) {
				continue;
			}
			MemoryBlock block = memory.getBlock(ptr);
			if (block == null || block.getName().equals(MemoryBlock.EXTERNAL_BLOCK_NAME)) {
				continue;
			}
			if (pltStart == null) {
				pltStart = ptr;
			}
			pltEnd = ptr;
		}

		if (pltStart != null) {
			processLinkageTable("PLT", pltStart, pltEnd, monitor);
		}
	}

	/**
	 * Perform disassembly and markup of specified external linkage table which 
	 * consists of thunks to external functions.  If symbols are defined within the 
	 * linkage table, these will be transitioned to external functions.
	 * @param pltName name of PLT section for log messages
	 * @param minAddress minimum address of linkage table
	 * @param maxAddress maximum address of linkage table
	 * @param monitor task monitor
	 * @throws CancelledException task cancelled
	 */
	public void processLinkageTable(String pltName, Address minAddress, Address maxAddress,
			TaskMonitor monitor) throws CancelledException {

		// Disassemble section.  
		// Disassembly is only done so we can see all instructions since many
		// of them are unreachable after applying relocations
		disassemble(minAddress, maxAddress, program, monitor);

		// Any symbols in the linkage section should be converted to External function thunks 
		// This can be seen with ARM Android examples.
		int count = convertSymbolsToExternalFunctions(minAddress, maxAddress);
		if (count > 0) {
			log("Converted " + count + " " + pltName + " section symbols to external thunks");
		}
	}

	/**
	 * Convert all symbols over a specified range to thunks to external functions. 
	 * @param minAddress
	 * @param maxAddress
	 * @return number of symbols converted
	 */
	private int convertSymbolsToExternalFunctions(Address minAddress, Address maxAddress) {
		// use address set to avoid symbol iterator reset while making changes
		AddressSet set = new AddressSet();
		SymbolTable symbolTable = program.getSymbolTable();
		for (Symbol s : symbolTable.getPrimarySymbolIterator(minAddress, true)) {
			Address symAddr = s.getAddress();
			if (symAddr.compareTo(maxAddress) > 0) {
				break;
			}
			if (s.getSource() == SourceType.DEFAULT) {
				// skip dynamic labels and default thunk functions
				continue;
			}
			if (listing.getDataAt(symAddr) != null) {
				continue; // skip PLT locations with data
			}
			set.add(symAddr);
		}
		if (set.isEmpty()) {
			return 0;
		}
		for (Address addr : set.getAddresses(true)) {
			Symbol s = symbolTable.getPrimarySymbol(addr);
			elfLoadHelper.createExternalFunctionLinkage(s.getName(), addr, null);
		}
		return (int) set.getNumAddresses();
	}

	private void disassemble(Address start, Address end, Program prog, TaskMonitor monitor)
			throws CancelledException {
		DisassemblerMessageListener dml = msg -> {
			//don't care...
		};
		// TODO: Should we restrict disassembly or follows flows?
		AddressSet set = new AddressSet(start, end);
		Disassembler disassembler = Disassembler.getDisassembler(prog, monitor, dml);
		while (!set.isEmpty()) {
			monitor.checkCanceled();
			AddressSet disset = disassembler.disassemble(set.getMinAddress(), set, true);
			if (disset.isEmpty()) {
				// Stop on first error but discard error bookmark since
				// some plt sections are partly empty and must rely
				// on normal flow disassembly during analysis
				prog.getBookmarkManager().removeBookmarks(set, BookmarkType.ERROR,
					Disassembler.ERROR_BOOKMARK_CATEGORY, monitor);
				break;//we did not disassemble anything...
			}
			set.delete(disset);
		}
	}

	private Data createPointer(Address addr, boolean keepRefWhenValid)
			throws CodeUnitInsertionException {

		MemoryBlock block = memory.getBlock(addr);
		if (block == null || !block.isInitialized()) {
			return null;
		}
		int pointerSize = program.getDataTypeManager().getDataOrganization().getPointerSize();
		Pointer pointer = PointerDataType.dataType.clone(program.getDataTypeManager());
		if (elf.is32Bit() && pointerSize != 4) {
			pointer = Pointer32DataType.dataType;
		}
		else if (elf.is64Bit() && pointerSize != 8) {
			pointer = Pointer64DataType.dataType;
		}
		Data data = listing.getDataAt(addr);
		if (data == null || !pointer.isEquivalent(data.getDataType())) {
			if (data != null) {
				listing.clearCodeUnits(addr, addr.add(pointerSize - 1), false);
			}
			data = listing.createData(addr, pointer);
		}
		if (keepRefWhenValid && isValidPointer(data)) {
			setConstant(data);
		}
		else {
			removeMemRefs(data);
		}
		return data;
	}

	/**
	 * Set specified data as constant if contained within a writable block.  It can be helpful
	 * to the decompiler results if constant pointers are marked as such (e.g., GOT entries)
	 * @param data program data
	 */
	public static void setConstant(Data data) {
		Memory memory = data.getProgram().getMemory();
		MemoryBlock block = memory.getBlock(data.getAddress());
		if (!block.isWrite() || block.getName().startsWith(ElfSectionHeaderConstants.dot_got)) {
			// .got blocks will be force to read-only by ElfDefaultGotPltMarkup
			return;
		}
		data.setLong(MutabilitySettingsDefinition.MUTABILITY,
			MutabilitySettingsDefinition.CONSTANT);
	}

	/**
	 * Determine if pointerData refers to a valid memory address or symbol
	 * @param pointerData pointer data
	 * @return true if pointer data refers to valid memory address or symbol
	 */
	public static boolean isValidPointer(Data pointerData) {
		Program program = pointerData.getProgram();
		Memory memory = program.getMemory();
		Address refAddr = (Address) pointerData.getValue();
		if (memory.contains(refAddr)) {
			return true;
		}
		Symbol syms[] = program.getSymbolTable().getSymbols(refAddr);
		if (syms != null && syms.length > 0 && syms[0].getSource() != SourceType.DEFAULT) {
			return true;
		}
		return false;
	}

	private void removeMemRefs(Data data) {
		if (data != null) {
			Reference[] refs = data.getValueReferences();
			for (Reference ref : refs) {
				RemoveReferenceCmd cmd = new RemoveReferenceCmd(ref);
				cmd.applyTo(data.getProgram());
			}
		}
	}

	/**
	 * This is an ugly hack to catch pre-linked ARM shared libraries.  All entries in the .GOT should
	 * be either relocated, or point to a good location in the binary.  If they aren't a good address,
	 * then the base of the .so is most likely incorrect.  Shift it!
	 */
	private Address UglyImageBaseCheck(Data data, Address imageBase) {
		if (elf.e_machine() != ElfConstants.EM_ARM) {
			return null;
		}
		if (!elf.isSharedObject()) {
			return null;
		}
		if (imageBase != null) {
			return imageBase;
		}

		// Ugly hack for preLinked .so files
		//    if this is a .so and we come across an address that is not valid, not 0, not a relocation
		//      get the top of the address of the program.  See how many bytes it fits in
		Object dValue = data.getValue();
		if (dValue == null || !(dValue instanceof Address)) {
			return null;
		}
		Address daddr = (Address) dValue;
		if (memory.contains(daddr)) {
			return null;
		}
		if (daddr.getOffset() < 4) {
			return null;
		}
		if (program.getImageBase().getOffset() != 0) {
			return null;
		}
		if (program.getRelocationTable().getRelocation(data.getAddress()) != null) {
			return null;
		}
		MemoryBlock tBlock = memory.getBlock(".text");
		if (tBlock == null) {
			return null;
		}
		Address topAddr = tBlock.getEnd();
		long topVal = topAddr.getOffset();
		long byteMask = 0xffffffffffffffffL;
		while (topVal != 0) {
			byteMask <<= 8;
			topVal >>>= 8;
		}
		long newBase = daddr.getOffset() & byteMask;
		if (newBase == 0) {
			return null;
		}
		return daddr.getNewAddress(newBase);
	}
}
