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

import java.util.*;

import ghidra.app.cmd.refs.RemoveReferenceCmd;
import ghidra.program.disassemble.Disassembler;
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

	// When PLT head is known and named sections are missing this label will be placed at head of PLT
	private static final String PLT_HEAD_SYMBOL_NAME = "__PLT_HEAD";

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
			processDynamicPLTGOT(ElfDynamicType.DT_PLTGOT, ElfDynamicType.DT_JMPREL, monitor);
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

	private static class PltGotSymbol implements Comparable<PltGotSymbol> {
		final ElfSymbol elfSymbol;
		final long offset;

		PltGotSymbol(ElfSymbol elfSymbol, long offset) {
			this.elfSymbol = elfSymbol;
			this.offset = offset;
		}

		@Override
		public int compareTo(PltGotSymbol o) {
			return Long.compareUnsigned(offset, o.offset);
		}
	}

	// When scanning PLT for symbols the min/max entry size are used to control the search
	private static final int MAX_SUPPORTED_PLT_ENTRY_SIZE = 32;
	private static final int MIN_SUPPORTED_PLT_ENTRY_SIZE = 8;

	// When scanning PLT for symbol spacing this is the threashold used to stop the search
	// when the same spacing size is detected in an attempt to identify the PLT entry size
	private static final int PLT_SYMBOL_SAMPLE_COUNT_THRESHOLD = 10;

	/**
	 * Process GOT and associated PLT based upon specified dynamic table entries.
	 * The primary goal is to identify the bounds of the GOT and PLT and process
	 * any external symbols which may be defined within the PLT.  Processing of PLT
	 * is only critical if it contains external symbols which must be processed, otherwise
	 * they will likely resolve adequately during subsequent analysis.
	 * @param pltGotType dynamic type for dynamic PLTGOT lookup (identifies dynamic PLTGOT)
	 * @param pltGotRelType dynamic type for associated dynamic JMPREL lookup (identifies dynamic PLTGOT relocation table)
	 * @param monitor task monitor
	 * @throws CancelledException thrown if task cancelled
	 */
	private void processDynamicPLTGOT(ElfDynamicType pltGotType, ElfDynamicType pltGotRelType,
			TaskMonitor monitor) throws CancelledException {

		ElfDynamicTable dynamicTable = elf.getDynamicTable();
		if (dynamicTable == null || !dynamicTable.containsDynamicValue(pltGotType) ||
			!dynamicTable.containsDynamicValue(pltGotRelType)) {
			return;
		}

		AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
		long imageBaseAdj = elfLoadHelper.getImageBaseWordAdjustmentOffset();

		try {
			long relocTableAddr =
				elf.adjustAddressForPrelink(dynamicTable.getDynamicValue(pltGotRelType));

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

			// External dynamic symbol entries in the GOT, if any, will be placed
			// after any local symbol entries.  Local entries are assumed to have original 
			// bytes of zero, whereas non-local entries will refer to the PLT

			// While the dynamic value for pltGotType (e.g., DT_PLTGOT) identifies the start of 
			// dynamic GOT table it does not specify its length.  The associated relocation
			// table, identified by the dynamic value for pltGotRelType, will have a relocation
			// record for each PLT entry linked via the GOT.  The number of relocations matches
			// the number of PLT entries and the one with the greatest offset correspionds
			// to the last GOT entry.  Unfortuntely, the length of each PLT entry and initial
			// PLT head is unknown.  If the binary has not placed external symbols within the PLT
			// processing and disassembly of the PLT may be skipped.

			long pltgot = elf.adjustAddressForPrelink(
				dynamicTable.getDynamicValue(pltGotType));
			Address gotStart = defaultSpace.getAddress(pltgot + imageBaseAdj);

			ElfRelocation[] relocations = relocationTable.getRelocations();
			ElfSymbolTable associatedSymbolTable = relocationTable.getAssociatedSymbolTable();
			if (associatedSymbolTable == null) {
				return;
			}

			// Create ordered list of PLTGOT symbols based upon offset with GOT.
			// It assumed that the PLT entry sequence will match this list.
			ElfSymbol[] symbols = associatedSymbolTable.getSymbols();
			List<PltGotSymbol> pltGotSymbols = new ArrayList<>();
			for (ElfRelocation reloc : relocations) {
				pltGotSymbols
						.add(new PltGotSymbol(symbols[reloc.getSymbolIndex()], reloc.getOffset()));
			}
			Collections.sort(pltGotSymbols);

			// Identify end of GOT table based upon relocation offsets
			long maxGotOffset = pltGotSymbols.get(pltGotSymbols.size() - 1).offset;
			Address gotEnd = defaultSpace.getAddress(maxGotOffset + imageBaseAdj);

			processGOT(gotStart, gotEnd, monitor);

			//
			// Examine the first two GOT entries which correspond to the relocations (i.e., pltGotSymbols).
			// An adjusted address from the original bytes is computed.  These will point into the PLT.  
			// These two pointers will either refer to the same address (i.e., PLT head) or different 
			// addresses which correspond to the first two PLT entries.  While likely offcut into each PLT 
			// entry, the differing PLT addresses can be used to identify the PLT entry size/spacing but 
			// not the top of PLT.  If symbols are present within the PLT for each entry, they may 
			// be used to identify the PLT entry size/spacing and will be converted to external symbols.
			// 

			long pltEntryCount = pltGotSymbols.size();

			// Get original bytes, converted to addresses, for first two PLT/GOT symbols
			Address pltAddr1 = null;
			Address pltAddr2 = null;
			for (PltGotSymbol pltGotSym : pltGotSymbols) {
				Address gotEntryAddr = defaultSpace.getAddress(pltGotSym.offset + imageBaseAdj);
				long originalGotEntry = elfLoadHelper.getOriginalValue(gotEntryAddr, true);
				if (originalGotEntry == 0) {
					return; // unexpected original bytes for PLTGOT entry - skip PLT processing
				}
				if (pltAddr1 == null) {
					pltAddr1 = defaultSpace.getAddress(originalGotEntry + imageBaseAdj);
				}
				else {
					pltAddr2 = defaultSpace.getAddress(originalGotEntry + imageBaseAdj);
					break;
				}
			}
			if (pltAddr2 == null) {
				return; // unable to find two GOT entries which refer to PLT - skip PLT processing
			}

			// NOTE: This approach assumes that all PLT entries have the same structure (i.e., instruction sequence)
			long pltSpacing = pltAddr2.subtract(pltAddr1);
			if (pltSpacing < 0 || pltSpacing > MAX_SUPPORTED_PLT_ENTRY_SIZE ||
				(pltSpacing % 2) != 0) {
				return; // unsupported PLT entry size - skip PLT processing
			}

			Address minSymbolSearchAddress;
			long symbolSearchSpacing; // nominal PLT entry size for computing maxSymbolSearchAddress

			Address firstPltEntryAddr = null; // may be offcut within first PLT entry

			if (pltSpacing == 0) { // Entries have same original bytes which refer to PLT head
				Function pltHeadFunc = elfLoadHelper.createOneByteFunction(null, pltAddr1, false);
				if (pltHeadFunc.getSymbol().getSource() == SourceType.DEFAULT) {
					try {
						pltHeadFunc.setName(PLT_HEAD_SYMBOL_NAME, SourceType.ANALYSIS);
					}
					catch (DuplicateNameException | InvalidInputException e) {
						// Ignore - unexpected
					}
				}

				// PLT spacing is not known.  pltAddr1 is PLT head
				minSymbolSearchAddress = pltAddr1.next();

				// Use conservative PLT entry size when computing address limit for PLT symbol search.
				// For a PLT with an actual entry size of 16 this will reduce the scan to less than half 
				// of the PLT.  This should only present an issue for very small PLTs or those 
				// with sparsely placed symbols.
				symbolSearchSpacing = MIN_SUPPORTED_PLT_ENTRY_SIZE;
			}
			else {
				// PLT spacing is known, but start of entry and head is not known.  pltAddr1 points to middle of first PLT entry (not head).
				firstPltEntryAddr = pltAddr1;
				minSymbolSearchAddress = pltAddr1.subtract(pltSpacing - 1); // try to avoid picking up symbol which may be at head
				symbolSearchSpacing = pltSpacing;
			}

			// Attempt to find symbols located within the PLT.
			Address maxSymbolSearchAddress =
				minSymbolSearchAddress.add(pltEntryCount * symbolSearchSpacing);

			// Scan symbols within PLT; helps to identify start of first entry and PLT entry size/spacing if unknown
			Symbol firstSymbol = null;
			Symbol lastSymbol = null;
			long discoveredPltSpacing = Long.MAX_VALUE;
			Map<Long, Integer> spacingCounts = new HashMap<>();
			for (Symbol sym : elfLoadHelper.getProgram()
					.getSymbolTable()
					.getSymbolIterator(minSymbolSearchAddress, true)) {
				if (sym.getSource() == SourceType.DEFAULT) {
					continue;
				}
				Address addr = sym.getAddress();
				if (addr.compareTo(maxSymbolSearchAddress) > 0) {
					break;
				}
				if (firstSymbol == null) {
					firstSymbol = sym;
				}
				if (pltSpacing == 0) {
					// Collect spacing samples if PLT spacing is unknown
					if (lastSymbol != null) {
						long spacing = addr.subtract(lastSymbol.getAddress());
						if (spacing > MAX_SUPPORTED_PLT_ENTRY_SIZE) {
							lastSymbol = null; // reset on large symbol spacing
							continue;
						}
						int count =
							spacingCounts.compute(spacing, (k, v) -> (v == null) ? 1 : v + 1);
						discoveredPltSpacing = Math.min(discoveredPltSpacing, spacing);
						if (count == PLT_SYMBOL_SAMPLE_COUNT_THRESHOLD) {
							break; // stop on 10 occurances of the same spacing (rather arbitrary sample limit)
						}
					}
					lastSymbol = sym;
				}
			}

			if (pltSpacing == 0) {
				if (discoveredPltSpacing == Long.MAX_VALUE ||
					spacingCounts.get(discoveredPltSpacing) == 1) { // NOTE: required number of symbol-spacing samples could be increased from 1
					return; // PLT spacing not determined / too large or insufficient PLT symbols - skip PLT processing
				}
				pltSpacing = discoveredPltSpacing;
			}

			if (firstSymbol != null) {
				// use PLT symbol if found to identify start of first PLT entry
				int firstSymbolEntryIndex = -1;
				Address firstSymbolAddr = firstSymbol.getAddress();
				int entryIndex = 0;
				for (PltGotSymbol entrySymbol : pltGotSymbols) {
					if (firstSymbolAddr
							.equals(elfLoadHelper.getElfSymbolAddress(entrySymbol.elfSymbol))) {
						firstSymbolEntryIndex = entryIndex;
						break;
					}
					++entryIndex;
				}
				if (firstSymbolEntryIndex >= 0) {
					firstPltEntryAddr = firstSymbolAddr;
					if (firstSymbolEntryIndex > 0) {
						firstPltEntryAddr =
							firstPltEntryAddr.subtract(firstSymbolEntryIndex * pltSpacing);
					}
				}
			}

			if (firstPltEntryAddr == null) {
				return; // failed to identify first PLT entry - skip PLT processing
			}

			Address pltEnd = firstPltEntryAddr.add(pltSpacing * (pltEntryCount - 1));
			processLinkageTable("PLT", firstPltEntryAddr, pltEnd, monitor);
		}
		catch (Exception e) {
			String msg = "Failed to process " + pltGotType + ": " + e.getMessage();
			log(msg);
			Msg.error(this, msg, e);
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

		// Bail if GOT was previously marked-up or not within initialized memory
		MemoryBlock block = memory.getBlock(gotStart);
		if (block == null || !block.isInitialized()) {
			return; // unsupported memory region - skip GOT processing
		}
		Data data = program.getListing().getDataAt(gotStart);
		if (data == null || !Undefined.isUndefined(data.getDataType())) {
			return; // evidence of prior markup - skip GOT processing
		}

		try {
			// Fixup first GOT entry which frequently refers to _DYNAMIC but generally lacks relocation (e.g. .got.plt)
			ElfDynamicTable dynamicTable = elf.getDynamicTable();
			long imageBaseAdj = elfLoadHelper.getImageBaseWordAdjustmentOffset();
			if (dynamicTable != null && imageBaseAdj != 0) {
				long entry1Value = elfLoadHelper.getOriginalValue(gotStart, false);
				if (entry1Value == dynamicTable.getAddressOffset()) {
					// TODO: record artificial relative relocation for reversion/export concerns
					entry1Value += imageBaseAdj; // adjust first entry value
					if (elf.is64Bit()) {
						memory.setLong(gotStart, entry1Value);
					}
					else {
						memory.setInt(gotStart, (int) entry1Value);
					}
				}
			}

			boolean imageBaseAlreadySet = elf.isPreLinked();

			Address newImageBase = null;
			Address nextGotAddr = gotStart;
			while (nextGotAddr.compareTo(gotEnd) <= 0) {

				data = createPointer(nextGotAddr, true);
				if (data == null) {
					break;
				}

				try {
					nextGotAddr = data.getMaxAddress().add(1);
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
		catch (Exception e) {
			String msg = "Failed to process GOT at " + gotStart + ": " + e.getMessage();
			log(msg);
			Msg.error(this, msg, e);
		}
	}

	private void processPLTSection(TaskMonitor monitor) throws CancelledException {

		// TODO: May want to consider using analysis to fully disassemble PLT, we only 
		// really need to migrate external symbols contained within the PLT

		// FIXME: Code needs help ... bad assumption about PLT head size (e.g., 16)
		int assumedPltHeadSize = 16;

		if (elf.isRelocatable()) {
			return; //relocatable files do not have .PLT sections
		}

		MemoryBlock pltBlock = memory.getBlock(ElfSectionHeaderConstants.dot_plt);
		// TODO: This is a band-aid since there are many PLT implementations and this assumes only one.
		if (pltBlock == null || !pltBlock.isExecute() || pltBlock.getSize() <= assumedPltHeadSize) {
			return;
		}

		int skipPointers = assumedPltHeadSize;

		// ARM, AARCH64 and others may not store pointers at start of .plt
		if (elf.e_machine() == ElfConstants.EM_ARM || elf.e_machine() == ElfConstants.EM_AARCH64) {
			skipPointers = 0; // disassemble entire PLT
		}

		// Process PLT section
		Address minAddress = pltBlock.getStart().add(skipPointers);
		Address maxAddress = pltBlock.getEnd();
		processLinkageTable(ElfSectionHeaderConstants.dot_plt, minAddress, maxAddress, monitor);
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

		try {
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
		catch (Exception e) {
			String msg =
				"Failed to process " + pltName + " at " + minAddress + ": " + e.getMessage();
			log(msg);
			Msg.error(this, msg, e);
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
		// TODO: Should we restrict disassembly or follows flows?
		AddressSet set = new AddressSet(start, end);
		Disassembler disassembler = Disassembler.getDisassembler(prog, monitor, m -> {
			/* silent */});
		while (!set.isEmpty()) {
			monitor.checkCanceled();
			AddressSet disset = disassembler.disassemble(set.getMinAddress(), null, true);
			if (disset.isEmpty()) {
				// Stop on first error but discard error bookmark since
				// some plt sections are partly empty and must rely
				// on normal flow disassembly during analysis
				prog.getBookmarkManager()
						.removeBookmarks(set, BookmarkType.ERROR,
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
		Symbol primary = program.getSymbolTable().getPrimarySymbol(refAddr);
		return primary != null && primary.getSource() != SourceType.DEFAULT;
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
		// TODO: Find sample - e.g., ARM .so - seems too late in import processing to change image base 
		//       if any relocations have been applied.
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
