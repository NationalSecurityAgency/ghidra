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
import java.util.Optional;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.mem.*;

/**
 * Provides information about the source of a byte value at an address including the file it 
 * came from, the offset into that file, and the original value of that byte.
 */
public class AddressSourceInfo {

	private Address address;
	private MemoryBlock block;
	private FileBytes fileBytes;
	private MemoryBlockSourceInfo sourceInfo;
	private AddressSourceInfo mappedInfo;
	private Memory memory;

	public AddressSourceInfo(Memory memory, Address address, MemoryBlock block) {
		this.memory = memory;
		this.address = address;
		this.block = block;
		sourceInfo = getContainingInfo();
		fileBytes = sourceInfo.getFileBytes().orElse(null);
	}


	/**
	 * Returns the address for which this object provides byte source information.
	 * @return  the address for which this object provides byte source information.
	 */
	public Address getAddress() {
		return address;
	}

	/**
	 * Returns the offset into the originally imported file that provided the byte value for the
	 * associated address or -1 if there is no source information for this location.
	 * @return  the offset into the originally imported file that provided the byte value for the
	 * associated address.
	 */
	public long getFileOffset() {
		if (mappedInfo != null) {
			return mappedInfo.getFileOffset();
		}

		if (fileBytes != null) {
			return sourceInfo.getFileBytesOffset(address) + fileBytes.getFileOffset();
		}
		return -1;
	}

	/**
	 * Returns the filename of the originally imported file that provided the byte value for the
	 * associated address or null if there is no source information for this location.
	 * @return the filename of the originally imported file that provided the byte value for the
	 * associated address or null if there is no source information for this location.
	 */
	public String getFileName() {
		if (mappedInfo != null) {
			return mappedInfo.getFileName();
		}
		if (fileBytes != null) {
			return fileBytes.getFilename();
		}
		return null;
	}

	/**
	 * Returns the original byte value from the imported file that provided the byte value for the
	 * associated address or 0 if there is no source information for this location.
	 * @return the original byte value from the imported file that provided the byte value for the
	 * associated address or 0 if there is no source information for this location.
	 * @throws IOException if an io error occurs reading the program database.
	 */
	public byte getOriginalValue() throws IOException {
		if (mappedInfo != null) {
			return mappedInfo.getOriginalValue();
		}
		if (fileBytes != null) {
			return fileBytes.getOriginalByte(getFileOffset());
		}
		return 0;
	}

	/**
	 * Returns the {@link MemoryBlockSourceInfo} for the region surround this info's location.
	 * @return  the {@link MemoryBlockSourceInfo} for the region surround this info's location.
	 */
	public MemoryBlockSourceInfo getMemoryBlockSourceInfo() {
		return sourceInfo;
	}

	private MemoryBlockSourceInfo getContainingInfo() {
		List<MemoryBlockSourceInfo> sourceInfos = block.getSourceInfos();
		for (MemoryBlockSourceInfo info : sourceInfos) {
			if (info.contains(address)) {
				Optional<AddressRange> mappedRangeOptional = info.getMappedRange();
				if (mappedRangeOptional.isPresent()) {
					mappedInfo = getMappedSourceInfo(info, mappedRangeOptional.get());
				}
				return info;
			}
		}
		return null;
	}

	private AddressSourceInfo getMappedSourceInfo(MemoryBlockSourceInfo info, AddressRange addressRange) {
		Address mappedAddress =
			addressRange.getMinAddress().add(address.subtract(info.getMinAddress()));
		MemoryBlock mappedBlock = memory.getBlock(mappedAddress);
		if (mappedBlock == null) {
			return null;
		}
		return new AddressSourceInfo(memory, mappedAddress, mappedBlock);
	}
}
