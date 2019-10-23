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
 * Class for handling byte mapped memory sub blocks
 */
class ByteMappedSubMemoryBlock extends SubMemoryBlock {

	private final MemoryMapDB memMap;
	private final Address mappedAddress;
	private boolean ioPending;

	ByteMappedSubMemoryBlock(MemoryMapDBAdapter adapter, Record record) {
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
			new MemoryAccessException("Cyclic Access");
		}
		try {
			ioPending = true;
			return memMap.getByte(mappedAddress.addNoWrap(offsetInSubBlock));
		}
		catch (AddressOverflowException e) {
			throw new MemoryAccessException("No memory at address");
		}
		finally {
			ioPending = false;
		}
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
			return memMap.getBytes(mappedAddress.addNoWrap(offsetInSubBlock), b, off, len);
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
			memMap.setByte(mappedAddress.addNoWrap(offsetInSubBlock), b);
		}
		catch (AddressOverflowException e) {
			throw new MemoryAccessException("No memory at address");
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
			memMap.setBytes(mappedAddress.addNoWrap(offsetInSubBlock), b, off,
				len);
			return len;
		}
		catch (AddressOverflowException e) {
			throw new MemoryAccessException("No memory at address");
		}
		finally {
			ioPending = false;
		}
	}

	public AddressRange getMappedRange() {
		Address endMappedAddress = mappedAddress.add(subBlockLength - 1);
		return new AddressRangeImpl(mappedAddress, endMappedAddress);
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
		return MemoryBlockType.BYTE_MAPPED;
	}

	@Override
	protected SubMemoryBlock split(long memBlockOffset) throws IOException {
		// convert from offset in block to offset in this sub block
		int offset = (int) (memBlockOffset - subBlockOffset);
		long newLength = subBlockLength - offset;
		subBlockLength = offset;
		record.setLongValue(MemoryMapDBAdapter.SUB_LENGTH_COL, subBlockLength);
		adapter.updateSubBlockRecord(record);

		Address newAddr = mappedAddress.add(offset);
		AddressMapDB addressMap = adapter.getMemoryMap().getAddressMap();
		long encodedAddr = addressMap.getKey(newAddr, true);

		Record newSubRecord = adapter.createSubBlockRecord(0, 0, newLength,
			MemoryMapDBAdapter.SUB_TYPE_BYTE_MAPPED, 0, encodedAddr);

		return new ByteMappedSubMemoryBlock(adapter, newSubRecord);
	}

	@Override
	protected String getDescription() {
		return "Byte Mapped: " + mappedAddress;
	}

	@Override
	protected ByteSourceRangeList getByteSourceRangeList(MemoryBlock block, Address start,
			long offset, long size) {
		ByteSourceRangeList result = new ByteSourceRangeList();
		long relativeOffset = offset - subBlockOffset;
		Address startAddress = mappedAddress.add(relativeOffset);
		Address endAddress = startAddress.add(size - 1);
		List<MemoryBlockDB> blocks = memMap.getBlocks(startAddress, endAddress);
		for (MemoryBlockDB mappedBlock : blocks) {
			Address startInBlock = max(mappedBlock.getStart(), startAddress);
			Address endInBlock = min(mappedBlock.getEnd(), endAddress);
			AddressRange blockRange = new AddressRangeImpl(startInBlock, endInBlock);
			ByteSourceRangeList ranges =
				mappedBlock.getByteSourceRangeList(startInBlock, blockRange.getLength());
			for (ByteSourceRange bsRange : ranges) {
				result.add(translate(block, bsRange, start, relativeOffset));
			}
		}
		return result;
	}

	private ByteSourceRange translate(MemoryBlock block, ByteSourceRange bsRange, Address addr,
			long relativeOffset) {
		Address mappedStart = bsRange.getStart();
		long offset = mappedStart.subtract(mappedAddress);
		Address start = addr.add(offset - relativeOffset);
		return new ByteSourceRange(block, start, bsRange.getSize(), bsRange.getSourceId(),
			bsRange.getOffset());
	}

	Address min(Address a1, Address a2) {
		return a1.compareTo(a2) <= 0 ? a1 : a2;
	}

	Address max(Address a1, Address a2) {
		return a1.compareTo(a2) >= 0 ? a1 : a2;
	}

}
