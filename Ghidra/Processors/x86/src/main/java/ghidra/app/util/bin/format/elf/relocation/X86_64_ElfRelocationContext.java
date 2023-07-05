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
import ghidra.program.model.address.*;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NotFoundException;

/**
 * <code>X86_64_ElfRelocationContext</code> provides ability to generate a
 * Global Offset Table (GOT) to facilitate GOT related relocations encountered within 
 * object modules.
 */
class X86_64_ElfRelocationContext extends ElfRelocationContext {

	private AddressRange allocatedGotLimits;
	private Address allocatedGotAddress;
	private Address lastAllocatedGotEntryAddress;
	private Address nextAllocatedGotEntryAddress;

	private Map<Long, Address> gotMap;

	X86_64_ElfRelocationContext(X86_64_ElfRelocationHandler handler, ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		super(handler, loadHelper, symbolMap);
	}

	@Override
	public long getSymbolValue(ElfSymbol symbol) {
		long symbolValue = super.getSymbolValue(symbol);
		if (symbolValue == 0 && ElfConstants.GOT_SYMBOL_NAME.equals(symbol.getNameAsString())) {
			Address gotAddr = allocateGot();
			if (gotAddr != null) {
				return gotAddr.getOffset();
			}
		}
		return symbolValue;
	}

	@Override
	public long getGOTValue() throws NotFoundException {
		try {
			return super.getGOTValue();
		}
		catch (NotFoundException e) {
			Address gotAddr = allocateGot();
			if (gotAddr != null) {
				return gotAddr.getOffset();
			}
			throw e;
		}
	}

	private ElfSymbol findGotElfSymbol() {
		for (ElfSymbolTable st : getElfHeader().getSymbolTables()) {
			for (ElfSymbol s : st.getSymbols()) {
				if (ElfConstants.GOT_SYMBOL_NAME.equals(s.getNameAsString())) {
					return s;
				}
			}
		}
		return null;
	}

	private int computeRequiredGotSize() {
		// NOTE: GOT allocation calculation assumes all GOT entries correspond to a specific
		// symbol and not a computed offset.  This assumption may need to be revised based upon 
		// uses of getGotEntryAddress method
		Set<Object> uniqueSymbolValues = new HashSet<>();
		for (ElfRelocationTable rt : getElfHeader().getRelocationTables()) {
			ElfSymbolTable st = rt.getAssociatedSymbolTable();
			if (st == null) {
				continue;
			}
			for (ElfRelocation r : rt.getRelocations()) {
				int symbolIndex = r.getSymbolIndex();
				if (!requiresGotEntry(r) || symbolIndex == 0) {
					continue;
				}
				ElfSymbol elfSymbol = st.getSymbol(symbolIndex);
				if (elfSymbol == null) {
					continue;
				}
				long value = elfSymbol.getValue();
				Object uniqueValue = value == 0 ? elfSymbol.getNameAsString() : Long.valueOf(value);
				uniqueSymbolValues.add(uniqueValue);
			}
		}
		return Math.max(8, uniqueSymbolValues.size() * 8);
	}

	private boolean requiresGotEntry(ElfRelocation r) {
		switch (r.getType()) {
			case X86_64_ElfRelocationConstants.R_X86_64_GOTPCREL:
			case X86_64_ElfRelocationConstants.R_X86_64_GOTOFF64:
			case X86_64_ElfRelocationConstants.R_X86_64_GOTPC32:
			case X86_64_ElfRelocationConstants.R_X86_64_GOT64:
			case X86_64_ElfRelocationConstants.R_X86_64_GOTPCREL64:
			case X86_64_ElfRelocationConstants.R_X86_64_GOTPC64:
			case X86_64_ElfRelocationConstants.R_X86_64_GOTPCRELX:
			case X86_64_ElfRelocationConstants.R_X86_64_REX_GOTPCRELX:
				return true;
			default:
				return false;
		}
	}

	private Address allocateGot() {

		allocatedGotAddress = Address.NO_ADDRESS;
		nextAllocatedGotEntryAddress = Address.NO_ADDRESS;

		ElfSymbol gotElfSymbol = findGotElfSymbol();

		if (gotElfSymbol == null && !getElfHeader().isRelocatable()) {
			loadHelper.log(
				"GOT allocatiom failed. " + ElfConstants.GOT_SYMBOL_NAME + " not defined");
			return null;
		}

		if (gotElfSymbol != null && getSymbolAddress(gotElfSymbol) != null) {
			throw new AssertException(ElfConstants.GOT_SYMBOL_NAME + " already allocated");
		}

		int alignment = getLoadAdapter().getLinkageBlockAlignment();
		allocatedGotLimits =
			getLoadHelper().allocateLinkageBlock(alignment, computeRequiredGotSize(),
				ElfRelocationHandler.GOT_BLOCK_NAME);
		if (allocatedGotLimits != null &&
			allocatedGotLimits.getMinAddress().getOffset() < Integer.MAX_VALUE) {
			// GOT must fall within first 32-bit segment
			if (gotElfSymbol != null) {
				symbolMap.put(gotElfSymbol, allocatedGotLimits.getMinAddress());
			}
			allocatedGotAddress = allocatedGotLimits.getMinAddress();
			nextAllocatedGotEntryAddress = allocatedGotAddress;
			gotMap = new HashMap<>();
			loadHelper.log("Created " + ElfRelocationHandler.GOT_BLOCK_NAME +
				" block required for GOT relocation processing");
			return allocatedGotAddress;
		}

		loadHelper.log("Failed to allocate GOT block required for relocation processing");
		return null;
	}

	/**
	 * Allocate the next section GOT entry location.  If GOT has not been allocated an attempt
	 * will be made to create one.  If allocated gotMap will also be established.
	 * @return Address of GOT entry or {@link Address#NO_ADDRESS} if unable to allocate.
	 */
	private Address getNextAllocatedGotEntryAddress() {
		if (nextAllocatedGotEntryAddress == null) {
			allocateGot();
		}

		Address addr = nextAllocatedGotEntryAddress;
		if (addr == Address.NO_ADDRESS) {
			return Address.NO_ADDRESS; // insufficient space in got
		}

		try {
			// verify that entry fits in got
			int pointerSize = loadHelper.getProgram().getDefaultPointerSize();
			Address lastAddr = nextAllocatedGotEntryAddress.addNoWrap(pointerSize - 1);
			if (allocatedGotLimits.contains(lastAddr)) {
				// entry fits in got - update and return entry address
				lastAllocatedGotEntryAddress = lastAddr;
				nextAllocatedGotEntryAddress = lastAllocatedGotEntryAddress.addNoWrap(1);
				if (!allocatedGotLimits.contains(nextAllocatedGotEntryAddress)) {
					// allocated got space fully consumed
					nextAllocatedGotEntryAddress = Address.NO_ADDRESS;
				}
				return addr;
			}
		}
		catch (AddressOverflowException e) {
			// ignore
		}

		// insufficient space in got - fail future allocation attempts
		nextAllocatedGotEntryAddress = Address.NO_ADDRESS;
		return Address.NO_ADDRESS;
	}

	/**
	 * Get or allocate a GOT entry for the specified symbolValue.
	 * NOTE: This is restricted to object modules only which do not of a GOT.
	 * @param symbolValue symbol value
	 * @return GOT entry address or null if unable to allocate
	 */
	public Address getGotEntryAddress(long symbolValue) {
		Address addr = null;
		if (gotMap != null) {
			addr = gotMap.get(symbolValue);
		}
		if (addr == null) {
			addr = getNextAllocatedGotEntryAddress();
			if (gotMap != null) {
				gotMap.put(symbolValue, addr);
			}
		}
		return addr == Address.NO_ADDRESS ? null : addr;
	}

	/**
	 * Flush the section GOT table to a new %got memory block
	 */
	private void createGot() {
		if (lastAllocatedGotEntryAddress == null) {
			return;
		}
		int size = (int) lastAllocatedGotEntryAddress.subtract(allocatedGotAddress) + 1;
		try {
			MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, false,
				ElfRelocationHandler.GOT_BLOCK_NAME, allocatedGotAddress, size,
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

	@Override
	public void dispose() {

		// Generate the object module GOT table if required
		createGot();

		super.dispose();
	}
}
