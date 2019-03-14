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
package ghidra.program.database.mem;

import java.io.IOException;

import db.Record;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

/**
 * Class to handle memory blocks that are "overlayed" on other blocks. In other words, this
 * block just maps request for bytes from one address to another.  It also handles bit
 * overlay blocks, in which case bit value requests are translated into a byte/bit into another
 * block.
 */
class OverlayMemoryBlockDB extends MemoryBlockDB implements MappedMemoryBlock {
	// ioPending is flag used to prevent cyclic memory access.  Since this memory
	// block uses memory to resolve its reads and writes, we have to be careful that
	// some other block that this block uses, doesn't also use this block in return.

	private boolean ioPending;
	private static final MemoryAccessException IOPENDING_EXCEPTION =
		new MemoryAccessException("Cyclic Access");

	private static final MemoryAccessException MEMORY_ACCESS_EXCEPTION =
		new MemoryAccessException("No memory at address");

	private Address overlayStart;
	private Address overlayEnd;
	private boolean bitOverlay;

	/**
	 * Constructs a new OverlayMemoryBlockDB
	 * @param adapter the memory block database adapter
	 * @param record the record for this block
	 * @param memMap the memory map manager
	 * @param bitOverlay if true this is a bit overlay memory.
	 * @throws IOException if a database IO error occurs.
	 */
	OverlayMemoryBlockDB(MemoryMapDBAdapter adapter, Record record, MemoryMapDB memMap)
			throws IOException {
		super(adapter, record, null, memMap);
	}

	@Override
	void refresh(Record lRecord) throws IOException {
		super.refresh(lRecord);
		this.bitOverlay = blockType == MemoryBlockType.BIT_MAPPED;
		long base = record.getLongValue(MemoryMapDBAdapter.OVERLAY_ADDR_COL);
		overlayStart = addrMap.decodeAddress(base);
		try {
			overlayEnd = overlayStart.addNoWrap((bitOverlay ? (length - 1) / 8 : (length - 1)));
		}
		catch (AddressOverflowException e) {
			throw new RuntimeException("Overlay range extends beyond address space");
		}
	}

	/**
	 * @see ghidra.program.model.mem.MappedMemoryBlock#getOverlayedMinAddress()
	 */
	@Override
	public Address getOverlayedMinAddress() {
		return overlayStart;
	}

	@Override
	Address getOverlayAddress(long offset) {
		return overlayStart.add(bitOverlay ? offset / 8 : offset);
	}

	private byte getBitOverlayByte(long blockOffset)
			throws AddressOverflowException, MemoryAccessException {
		Address otherAddr = overlayStart.addNoWrap(blockOffset / 8);
		byte b = memMap.getByte(otherAddr);
		return (byte) ((b >> (blockOffset % 8)) & 0x01);
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#getByte(ghidra.program.model.address.Address)
	 */
	@Override
	public byte getByte(Address addr) throws MemoryAccessException {
		memMap.lock.acquire();
		try {
			checkValid();
			if (ioPending) {
				throw IOPENDING_EXCEPTION;
			}
			ioPending = true;
			long offset = getBlockOffset(addr);
			if (bitOverlay) {
				return getBitOverlayByte(offset);
			}
			return memMap.getByte(overlayStart.addNoWrap(offset));
		}
		catch (AddressOverflowException e) {
			throw MEMORY_ACCESS_EXCEPTION;
		}
		finally {
			ioPending = false;
			memMap.lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#getBytes(ghidra.program.model.address.Address, byte, int, int)
	 */
	@Override
	public int getBytes(Address addr, byte[] bytes, int off, int len) throws MemoryAccessException {
		memMap.lock.acquire();
		try {
			checkValid();
			if (ioPending) {
				throw IOPENDING_EXCEPTION;
			}
			ioPending = true;
			long offset = getBlockOffset(addr);
			long size = getSize();
			if (len > size - (addr.subtract(startAddress))) {
				len = (int) (size - addr.subtract(startAddress));
			}
			if (bitOverlay) {
				for (int i = 0; i < len; i++) {
					bytes[i + off] = getBitOverlayByte(offset++);
				}
				return len;
			}
			return memMap.getBytes(overlayStart.addNoWrap(offset), bytes, off, len);
		}
		catch (AddressOverflowException e) {
			throw MEMORY_ACCESS_EXCEPTION;
		}
		finally {
			ioPending = false;
			memMap.lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#putByte(ghidra.program.model.address.Address, byte)
	 */
	@Override
	public void putByte(Address addr, byte b) throws MemoryAccessException {
		memMap.lock.acquire();
		try {
			checkValid();
			if (ioPending) {
				throw IOPENDING_EXCEPTION;
			}
			ioPending = true;
			long offset = getBlockOffset(addr);
			if (bitOverlay) {
				checkValid();
				doPutByte(overlayStart.add(offset / 8), (int) (offset % 8), b);
			}
			else {
				memMap.setByte(overlayStart.add(offset), b);
			}
		}
		finally {
			ioPending = false;
			memMap.lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#putBytes(ghidra.program.model.address.Address, byte, int, int)
	 */
	@Override
	public int putBytes(Address addr, byte[] b, int off, int len) throws MemoryAccessException {
		memMap.lock.acquire();
		try {
			checkValid();
			if (ioPending) {
				throw IOPENDING_EXCEPTION;
			}
			ioPending = true;
			long offset = getBlockOffset(addr);
			long size = getSize();
			if (len > size - (addr.subtract(startAddress))) {
				len = (int) (size - addr.subtract(startAddress));
			}
			if (bitOverlay) {
				for (int i = 0; i < len; i++) {
					doPutByte(overlayStart.add(offset / 8), (int) (offset % 8), b[off + i]);
					addr = addr.add(1);
					offset++;
				}
			}
			else {
				memMap.setBytes(overlayStart.add(offset), b, off, len);
			}
			return len;
		}
		finally {
			ioPending = false;
			memMap.lock.release();
		}
	}

	private void doPutByte(Address addr, int bitIndex, byte b) throws MemoryAccessException {
		ioPending = true;
		byte value = memMap.getByte(addr);
		int mask = 1 << (bitIndex % 8);
		if (b == 0) {
			value &= ~mask;
		}
		else {
			value |= mask;
		}
		memMap.setByte(addr, value);
	}

//	void dataChanged(Address addr, int cnt) {
//		Address endAddr = addr.addWrap(cnt);
//		if (addr.compareTo(overlayEnd) > 0 || endAddr.compareTo(overlayStart) < 0) {
//			return;
//		}
//		if (ioPending) {
//			return;
//		}
//		try {
//			ioPending = true;
//			Address minAddr = addr.compareTo(overlayStart) > 0 ? addr : overlayStart;
//			Address maxAddr = endAddr.compareTo(overlayEnd) < 0 ? endAddr : overlayEnd;
//			Address myStartAddr =
//				startAddress.add(minAddr.subtract(overlayStart) * (bitOverlay ? 8 : 1));
//			Address myEndAddr =
//				startAddress.add(maxAddr.subtract(overlayStart) * (bitOverlay ? 8 : 1));
//			memMap.fireBytesChanged(myStartAddr, (int) myEndAddr.subtract(myStartAddr) + 1);
//		}
//		finally {
//			ioPending = false;
//		}
//	}

	@Override
	public boolean isMapped() {
		return true;
	}

	@Override
	public AddressRange getOverlayedAddressRange() {
		return new AddressRangeImpl(overlayStart, overlayEnd);
	}
}
