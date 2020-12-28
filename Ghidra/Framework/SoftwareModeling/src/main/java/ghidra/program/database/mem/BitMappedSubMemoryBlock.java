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

import db.DBRecord;
import ghidra.program.database.map.AddressMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlockType;

/**
 * Class for handling bit mapped memory sub blocks
 */
class BitMappedSubMemoryBlock extends SubMemoryBlock {
	private final MemoryMapDB memMap;
	private final Address mappedAddress;
	private boolean ioPending;

	BitMappedSubMemoryBlock(MemoryMapDBAdapter adapter, DBRecord record) {
		super(adapter, record);
		this.memMap = adapter.getMemoryMap();
		AddressMapDB addressMap = memMap.getAddressMap();
		mappedAddress = addressMap.decodeAddress(
			record.getLongValue(MemoryMapDBAdapter.SUB_LONG_DATA2_COL), false);
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

	AddressRange getMappedRange() {
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

}
