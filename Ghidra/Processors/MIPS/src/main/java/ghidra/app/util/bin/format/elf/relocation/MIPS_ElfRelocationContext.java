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
package ghidra.app.util.bin.format.elf.relocation;

import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.extend.MIPS_ElfExtension;
import ghidra.app.util.bin.format.elf.relocation.MIPS_ElfRelocationHandler.MIPS_DeferredRelocation;
import ghidra.program.model.address.*;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NotFoundException;

/**
 * {@link MIPS_ElfRelocationContext} provides extended relocation context with the ability
 * to retain deferred relocation lists.  In addition, the ability to generate a section GOT
 * table is provided to facilitate relocations encountered within object modules.
 */
class MIPS_ElfRelocationContext extends ElfRelocationContext<MIPS_ElfRelocationHandler> {

	private LinkedList<MIPS_DeferredRelocation> hi16list = new LinkedList<>();
	private LinkedList<MIPS_DeferredRelocation> got16list = new LinkedList<>();

	private AddressRange sectionGotLimits;
	private Address sectionGotAddress;
	private Address lastSectionGotEntryAddress;
	private Address nextSectionGotEntryAddress;

	private Map<Long, Address> gotMap;

	boolean saveValueForNextReloc;
	boolean useSavedAddend = false;
	boolean savedAddendHasError = false;
	long savedAddend;

	ElfSymbol lastElfSymbol;
	Address lastSymbolAddr;

	MIPS_ElfRelocationContext(MIPS_ElfRelocationHandler handler, ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		super(handler, loadHelper, symbolMap);
	}

	@Override
	protected RelocationResult processRelocation(ElfRelocation relocation, ElfSymbol elfSymbol,
			Address relocationAddress) throws MemoryAccessException {

		lastSymbolAddr = null;
		lastElfSymbol = null;

		int typeId = relocation.getType();
		int symbolIndex = relocation.getSymbolIndex();

		saveValueForNextReloc = nextRelocationHasSameOffset(relocation);

		RelocationResult lastResult = RelocationResult.FAILURE;
		if (getElfHeader().is64Bit()) {

			MIPS_Elf64Relocation mips64Relocation = (MIPS_Elf64Relocation) relocation;

			// Each relocation can pack upto 3 relocations for 64-bit
			for (int n = 0; n < 3; n++) {

				if (n == 1) {
					symbolIndex = mips64Relocation.getSpecialSymbolIndex();
				}
				else {
					symbolIndex = 0;
				}

				int relocType = typeId & 0xff;
				typeId >>= 8;
				int nextRelocType = (n < 2) ? (typeId & 0xff) : 0;
				if (nextRelocType == MIPS_ElfRelocationType.R_MIPS_NONE.typeId) {
					saveValueForNextReloc = false;
				}

				RelocationResult result =
					doRelocate(mips64Relocation, relocationAddress, relocType, symbolIndex);

				if (result.status() == Status.FAILURE || result.status() == Status.UNSUPPORTED) {
					return result;
				}
				lastResult = result;

				if (nextRelocType == MIPS_ElfRelocationType.R_MIPS_NONE.typeId) {
					break;
				}
			}
			return lastResult;
		}

		return doRelocate(relocation, relocationAddress, typeId, symbolIndex);
	}

	private RelocationResult doRelocate(ElfRelocation relocation, Address relocationAddress,
			int relocType, int symbolIndex) throws MemoryAccessException {

		if (relocType == 0) {
			return RelocationResult.SKIPPED;
		}

		ElfSymbol elfSymbol = getSymbol(symbolIndex);
		Address symbolAddr = getSymbolAddress(elfSymbol);
		long symbolValue = getSymbolValue(elfSymbol);
		String symbolName = elfSymbol != null ? elfSymbol.getNameAsString() : null;

		MIPS_ElfRelocationType relocationType = handler.getRelocationType(relocType);
		if (relocationType == null) {
			handler.markAsUndefined(program, relocationAddress, relocType, symbolName, symbolIndex,
				getLog());
			return RelocationResult.UNSUPPORTED;
		}

		return handler.relocate(this, relocation, relocationType, relocationAddress,
			getSymbol(symbolIndex), symbolAddr, symbolValue, symbolName);
	}

	@Override
	public void endRelocationTableProcessing() {

		// Mark all deferred relocations which were never processed
		for (MIPS_DeferredRelocation reloc : hi16list) {
			reloc.markUnprocessed(this, "LO16 Relocation");
		}
		hi16list.clear();
		for (MIPS_DeferredRelocation reloc : got16list) {
			reloc.markUnprocessed(this, "LO16 Relocation");
		}
		got16list.clear();

		// Generate the section GOT table if required
		createGot();

		sectionGotLimits = null;
		sectionGotAddress = null;
		lastSectionGotEntryAddress = null;
		nextSectionGotEntryAddress = null;
		gotMap = null;
		useSavedAddend = false;
		savedAddendHasError = false;
		lastSymbolAddr = null;
		lastElfSymbol = null;

		super.endRelocationTableProcessing();
	}

	private void allocateSectionGot() {
		int alignment = getLoadAdapter().getLinkageBlockAlignment();
		sectionGotLimits =
			getLoadHelper().allocateLinkageBlock(alignment, 0x10000, getSectionGotName());
		sectionGotAddress =
			sectionGotLimits != null ? sectionGotLimits.getMinAddress() : Address.NO_ADDRESS;
		nextSectionGotEntryAddress = sectionGotAddress;
		if (sectionGotLimits == null) {
			loadHelper.log("Failed to allocate " + getSectionGotName() +
				" block required for relocation processing");
		}
		else {
			loadHelper.log("Created " + getSectionGotName() +
				" block required for relocation processing (gp=0x" +
				Long.toHexString(getGPValue()) + ")");
		}
	}

	/**
	 * Allocate the next section GOT entry location.
	 * @return Address of GOT entry or null if unable to allocate.
	 */
	private Address getNextSectionGotEntryAddress() {
		if (nextSectionGotEntryAddress == null) {
			allocateSectionGot();
		}
		Address addr = nextSectionGotEntryAddress;
		if (addr != Address.NO_ADDRESS) {
			try {
				int pointerSize = loadHelper.getProgram().getDefaultPointerSize();
				Address lastAddr = nextSectionGotEntryAddress.addNoWrap(pointerSize - 1);
				if (sectionGotLimits.contains(lastAddr)) {
					lastSectionGotEntryAddress = lastAddr;
					nextSectionGotEntryAddress = lastSectionGotEntryAddress.addNoWrap(1);
					if (!sectionGotLimits.contains(nextSectionGotEntryAddress)) {
						nextSectionGotEntryAddress = Address.NO_ADDRESS;
					}
				}
				else {
					// unable to allocation entry size
					nextSectionGotEntryAddress = Address.NO_ADDRESS;
					return Address.NO_ADDRESS;
				}
			}
			catch (AddressOverflowException e) {
				nextSectionGotEntryAddress = Address.NO_ADDRESS;
			}
		}
		return addr != Address.NO_ADDRESS ? addr : null;
	}

	/**
	 * Get the preferred GP.
	 * NOTE: This needs work to properly handle the use of multiple GP's
	 * @return preferred GP value or -1 if unable to determine GP
	 */
	public long getGPValue() {

		long gp = getAdjustedGPValue();
		if (gp == -1) {

			// TODO: we should probably not resort to assuming use of fabricated got so easily
			// since getAdjustedGPValue has rather limited capability at present

			// assume GP relative to fabricated GOT
			if (sectionGotAddress == null) {
				allocateSectionGot();
			}
			if (sectionGotAddress == Address.NO_ADDRESS) {
				return -1;
			}
			// gp is defined as 0x7ff0 byte offset into the global offset table
			return sectionGotAddress.getOffset() + 0x7ff0;
		}

		return gp;
	}

	@Override
	public boolean extractAddend() {
		return !relocationTable.hasAddendRelocations() && !useSavedAddend;
	}

	/**
	 * Determine if the next relocation has the same offset.
	 * If true, the computed value should be stored to savedAddend and
	 * useSaveAddend set true.
	 * @param relocation current relocation
	 * @return true if next relocation has same offset
	 */
	boolean nextRelocationHasSameOffset(ElfRelocation relocation) {
		ElfRelocation[] relocations = relocationTable.getRelocations();
		int relocIndex = relocation.getRelocationIndex();
		if (relocIndex < 0 || relocIndex >= (relocations.length - 1)) {
			return false;
		}
		return relocations[relocIndex].getOffset() == relocations[relocIndex + 1].getOffset() &&
			relocations[relocIndex + 1].getType() != MIPS_ElfRelocationType.R_MIPS_NONE.typeId;
	}

	/**
	 * Get or allocate a GOT entry for the specified symbolValue
	 * @param symbolValue symbol value to be added to GOT
	 * @return GOT entry address or null if unable to allocate
	 */
	public Address getSectionGotAddress(long symbolValue) {
		Address addr = null;
		if (gotMap == null) {
			gotMap = new HashMap<>();
		}
		else {
			addr = gotMap.get(symbolValue);
		}
		if (addr == null) {
			addr = getNextSectionGotEntryAddress();
			if (addr == null) {
				return null;
			}
			gotMap.put(symbolValue, addr);
		}
		return addr;
	}

	private String getSectionGotName() {
		String sectionName = relocationTable.getSectionToBeRelocated().getNameAsString();
		return ElfRelocationHandler.GOT_BLOCK_NAME + sectionName;
	}

	/**
	 * Flush the section GOT table to a new %got memory block
	 */
	private void createGot() {
		if (lastSectionGotEntryAddress == null) {
			return;
		}
		int size = (int) lastSectionGotEntryAddress.subtract(sectionGotAddress) + 1;
		String blockName = getSectionGotName();
		try {
			MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, false, blockName,
				sectionGotAddress, size,
				"NOTE: This block is artificial and allows ELF Relocations to work correctly",
				"Elf Loader", true, false, false, loadHelper.getLog());
			DataConverter converter =
				program.getMemory().isBigEndian() ? BigEndianDataConverter.INSTANCE
						: LittleEndianDataConverter.INSTANCE;
			for (long symbolValue : gotMap.keySet()) {
				Address addr = gotMap.get(symbolValue);
				byte[] bytes;
				if (program.getDefaultPointerSize() == 4) {
					bytes = converter.getBytes((int) symbolValue);
				}
				else {
					bytes = converter.getBytes(symbolValue);
				}
				block.putBytes(addr, bytes);
				loadHelper.createData(addr, PointerDataType.dataType);
			}
		}
		catch (MemoryAccessException e) {
			throw new AssertException(e); // unexpected
		}
	}

	/**
	 * Get the GP value
	 * @return adjusted GP value or -1 if _mips_gp_value symbol not defined.
	 */
	long getAdjustedGPValue() {

		// TODO: this is a simplified use of GP and could be incorrect when multiple GPs exist

		Symbol symbol = SymbolUtilities.getLabelOrFunctionSymbol(program,
			MIPS_ElfExtension.MIPS_GP_VALUE_SYMBOL, err -> getLog().appendMsg("MIPS_ELF", err));
		if (symbol == null) {
			return -1;
		}
		return symbol.getAddress().getOffset();
	}

	/**
	 * Get the GP0 value (from .reginfo and generated symbol)
	 * @return adjusted GP0 value or -1 if _mips_gp0_value symbol not defined.
	 */
	long getGP0Value() {
		Symbol symbol = SymbolUtilities.getLabelOrFunctionSymbol(program,
			MIPS_ElfExtension.MIPS_GP0_VALUE_SYMBOL, err -> getLog().appendMsg("MIPS_ELF", err));
		if (symbol == null) {
			return -1;
		}
		return symbol.getAddress().getOffset();
	}

	@Override
	public long getSymbolValue(ElfSymbol symbol) {
		if ("__gnu_local_gp".equals(symbol.getNameAsString())) {
			return getAdjustedGPValue(); // TODO: need to verify this case still
		}
		return super.getSymbolValue(symbol);
	}

	/**
	 * Iterate over deferred HI16 relocations.  Iterator may be used to remove
	 * entries as they are processed.
	 * @return HI16 relocation iterator
	 */
	Iterator<MIPS_DeferredRelocation> iterateHi16() {
		return hi16list.iterator();
	}

	/**
	 * Add HI16 relocation for deferred processing
	 * @param hi16reloc HI16 relocation
	 */
	void addHI16Relocation(MIPS_DeferredRelocation hi16reloc) {
		hi16list.add(hi16reloc);
	}

	/**
	 * Iterate over deferred GOT16 relocations.  Iterator may be used to remove
	 * entries as they are processed.
	 * @return GOT16 relocation iterator
	 */
	Iterator<MIPS_DeferredRelocation> iterateGot16() {
		return got16list.iterator();
	}

	/**
	 * Add GOT16 relocation for deferred processing
	 * @param got16reloc GOT16 relocation
	 */
	void addGOT16Relocation(MIPS_DeferredRelocation got16reloc) {
		got16list.add(got16reloc);
	}
}
