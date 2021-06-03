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
 * Class for handling byte mapped memory sub blocks
 */
class ByteMappedSubMemoryBlock extends SubMemoryBlock {

	private final MemoryMapDB memMap;
	private final Address mappedAddress;
	private final ByteMappingScheme byteMappingScheme;

	private boolean ioPending;

	ByteMappedSubMemoryBlock(MemoryMapDBAdapter adapter, DBRecord record) {
		super(adapter, record);
		this.memMap = adapter.getMemoryMap();
		AddressMapDB addressMap = memMap.getAddressMap();
		// TODO: ensure that mappedAddress is aligned with addressMask (trailing 0's of mask should be 0 in mappedAddress)
		mappedAddress = addressMap.decodeAddress(
			record.getLongValue(MemoryMapDBAdapter.SUB_LONG_DATA2_COL), false);
		int encodedMappingScheme = record.getIntValue(MemoryMapDBAdapter.SUB_INT_DATA1_COL);
		byteMappingScheme = new ByteMappingScheme(encodedMappingScheme);
	}

	ByteMappingScheme getByteMappingScheme() {
		return byteMappingScheme;
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
			Address sourceAddr =
				byteMappingScheme.getMappedSourceAddress(mappedAddress, offsetInSubBlock);
			return memMap.getByte(sourceAddr);
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
		// TODO: should array length be considered?
		len = (int) Math.min(len, available);
		if (ioPending) {
			new MemoryAccessException("Cyclic Access");
		}
		try {
			ioPending = true;
			return byteMappingScheme.getBytes(memMap, mappedAddress, offsetInSubBlock, b, off, len);
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
			Address sourceAddr =
				byteMappingScheme.getMappedSourceAddress(mappedAddress, offsetInSubBlock);
			memMap.setByte(sourceAddr, b);
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
			byteMappingScheme.setBytes(memMap, mappedAddress, offsetInSubBlock, b, off, len);
			return len;
		}
		catch (AddressOverflowException e) {
			throw new MemoryAccessException("No memory at address");
		}
		finally {
			ioPending = false;
		}
	}

	AddressRange getMappedRange() {
		Address endMappedAddress;
		try {
			endMappedAddress =
				byteMappingScheme.getMappedSourceAddress(mappedAddress, subBlockLength - 1);
		}
		catch (AddressOverflowException e) {
			// keep things happy
			endMappedAddress = mappedAddress.getAddressSpace().getMaxAddress();
		}
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

		// NOTE - GUI does not support any split of any byte-mapped blocks although API does.  
		//        Not sure we really need to support it for byte-mapped block.

		if (!byteMappingScheme.isOneToOneMapping()) {
			// byte-mapping scheme alignment restrictions would apply to split 
			// boundary if we were to support
			throw new UnsupportedOperationException(
				"split not supported for byte-mapped block with " + byteMappingScheme);
		}

		// convert from offset in block to offset in this sub block
		int offset = (int) (memBlockOffset - subBlockOffset);
		long newLength = subBlockLength - offset;
		subBlockLength = offset;
		record.setLongValue(MemoryMapDBAdapter.SUB_LENGTH_COL, subBlockLength);
		adapter.updateSubBlockRecord(record);

		Address newAddr = mappedAddress.add(offset);
		AddressMapDB addressMap = adapter.getMemoryMap().getAddressMap();
		long encodedAddr = addressMap.getKey(newAddr, true);

		DBRecord newSubRecord = adapter.createSubBlockRecord(0, 0, newLength,
			MemoryMapDBAdapter.SUB_TYPE_BYTE_MAPPED, 0, encodedAddr);

		return new ByteMappedSubMemoryBlock(adapter, newSubRecord);
	}

	@Override
	protected String getDescription() {
		return "Byte Mapped: " + mappedAddress + ", " + byteMappingScheme;
	}

}
