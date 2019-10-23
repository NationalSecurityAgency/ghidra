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
import java.util.List;

import db.Record;
import ghidra.program.database.map.AddressMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

/**
 * Class for handling bit mapped memory sub blocks
 */
class BitMappedSubMemoryBlock extends SubMemoryBlock {
	private final MemoryMapDB memMap;
	private final Address mappedAddress;
	private boolean ioPending;

	BitMappedSubMemoryBlock(MemoryMapDBAdapter adapter, Record record) {
		super(adapter, record);
		this.memMap = adapter.getMemoryMap();
		AddressMapDB addressMap = memMap.getAddressMap();
		mappedAddress = addressMap.decodeAddress(
			record.getLongValue(MemoryMapDBAdapter.SUB_SOURCE_OFFSET_COL), false);
	}

	@Override
	public boolean isInitialized() {
		return false;
	}

	@Override
	public byte getByte(long offsetInMemBlock) throws MemoryAccessException, IOException {
		long offsetInSubBlock = offsetInMemBlock - subBlockOffset;
		if (ioPending) {
			throw new MemoryAccessException("Cyclic Access");
		}
		try {
			ioPending = true;
			return getBitOverlayByte(offsetInSubBlock);
		}
		catch (AddressOverflowException e) {
			throw new MemoryAccessException("No memory at address");
		}
		finally {
			ioPending = false;
		}
	}

	public AddressRange getMappedRange() {
		Address endMappedAddress = mappedAddress.add((subBlockLength - 1) / 8);
		return new AddressRangeImpl(mappedAddress, endMappedAddress);
	}

	@Override
	public int getBytes(long offsetInMemBlock, byte[] b, int off, int len)
			throws MemoryAccessException, IOException {
		long offsetInSubBlock = offsetInMemBlock - subBlockOffset;
		long available = subBlockLength - offsetInSubBlock;
		len = (int) Math.min(len, available);
		if (ioPending) {
			new MemoryAccessException("Cyclic Access");
		}
		try {
			ioPending = true;
			for (int i = 0; i < len; i++) {
				b[i + off] = getBitOverlayByte(offsetInMemBlock++);
			}
			return len;
		}
		catch (AddressOverflowException e) {
			throw new MemoryAccessException("No memory at address");
		}
		finally {
			ioPending = false;
		}
	}

	@Override
	public void putByte(long offsetInMemBlock, byte b) throws MemoryAccessException, IOException {
		long offsetInSubBlock = offsetInMemBlock - subBlockOffset;
		try {
			if (ioPending) {
				new MemoryAccessException("Cyclic Access");
			}
			ioPending = true;
			doPutByte(mappedAddress.addNoWrap(offsetInSubBlock / 8), (int) (offsetInSubBlock % 8),
				b);
		}
		catch (AddressOverflowException e) {
			new MemoryAccessException("No memory at address");
		}
		finally {
			ioPending = false;
		}

	}

	@Override
	public int putBytes(long offsetInMemBlock, byte[] b, int off, int len)
			throws MemoryAccessException, IOException {
		long offsetInSubBlock = offsetInMemBlock - subBlockOffset;
		long available = subBlockLength - offsetInSubBlock;
		len = (int) Math.min(len, available);
		try {
			if (ioPending) {
				new MemoryAccessException("Cyclic Access");
			}
			ioPending = true;
			for (int i = 0; i < len; i++) {
				doPutByte(mappedAddress.addNoWrap(offsetInSubBlock / 8),
					(int) (offsetInSubBlock % 8), b[off + i]);
				offsetInSubBlock++;
			}
			return len;
		}
		catch (AddressOverflowException e) {
			throw new MemoryAccessException("No memory at address");
		}
		finally {
			ioPending = false;
		}
	}

	private byte getBitOverlayByte(long blockOffset)
			throws AddressOverflowException, MemoryAccessException {
		Address otherAddr = mappedAddress.addNoWrap(blockOffset / 8);
		byte b = memMap.getByte(otherAddr);
		return (byte) ((b >> (blockOffset % 8)) & 0x01);
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

	@Override
	protected boolean join(SubMemoryBlock sub2) {
		return false;
	}

	@Override
	protected boolean isMapped() {
		return true;
	}

	@Override
	protected MemoryBlockType getType() {
		return MemoryBlockType.BIT_MAPPED;
	}

	@Override
	protected SubMemoryBlock split(long offset) {
		throw new UnsupportedOperationException();
	}

	@Override
	protected String getDescription() {
		return "Bit Mapped: " + mappedAddress;
	}

	@Override
	protected ByteSourceRangeList getByteSourceRangeList(MemoryBlock block, Address start,
			long memBlockOffset,
			long size) {
		ByteSourceRangeList result = new ByteSourceRangeList();

		// Since mapped blocks are mapped onto other memory blocks, find those blocks and
		// handle each one separately

		// converts to byte space since 8 bytes in this block's space maps to 1 byte in real memory
		Address startMappedAddress = mappedAddress.add(memBlockOffset / 8);
		Address endMappedAddress = mappedAddress.add((memBlockOffset + size - 1) / 8);
		List<MemoryBlockDB> blocks = memMap.getBlocks(startMappedAddress, endMappedAddress);

		// for each block, get its ByteSourceSet and then translate that set back into this block's
		// addresses
		for (MemoryBlockDB mappedBlock : blocks) {
			Address startInBlock = max(mappedBlock.getStart(), startMappedAddress);
			Address endInBlock = min(mappedBlock.getEnd(), endMappedAddress);
			long blockSize = endInBlock.subtract(startInBlock) + 1;
			ByteSourceRangeList ranges =
				mappedBlock.getByteSourceRangeList(startInBlock, blockSize);
			for (ByteSourceRange bsRange : ranges) {
				result.add(translate(block, bsRange, start, memBlockOffset, size));
			}
		}
		return result;
	}

	// translates the ByteSourceRange back to addresse
	private ByteSourceRange translate(MemoryBlock block, ByteSourceRange bsRange, Address start,
			long offset,
			long bitLength) {
		Address startMappedAddress = mappedAddress.add(offset / 8);
		Address normalizedStart = start.subtract(offset % 8);
		long mappedOffsetFromStart = bsRange.getStart().subtract(startMappedAddress);
		long offsetFromStart = mappedOffsetFromStart * 8;
		Address startAddress = normalizedStart.add(offsetFromStart);

		return new BitMappedByteSourceRange(block, startAddress, bsRange.getSourceId(),
			bsRange.getOffset(), bsRange.getSize());
	}

	Address min(Address a1, Address a2) {
		return a1.compareTo(a2) <= 0 ? a1 : a2;
	}

	Address max(Address a1, Address a2) {
		return a1.compareTo(a2) >= 0 ? a1 : a2;
	}

}
