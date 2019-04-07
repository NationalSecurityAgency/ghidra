/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.macos.rm;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class ReferenceListEntry implements StructConverter {
	private short id;
	private short nameOffset;
	private byte  attributes;
	private int   dataOffset;
	private int   handle;

	private String _name;

	ReferenceListEntry(BinaryReader reader, ResourceMap map) throws IOException {
		id         = reader.readNextShort();
		nameOffset = reader.readNextShort();
		attributes = reader.readNextByte();
		dataOffset = read3ByteValue(reader);
		handle     = reader.readNextInt();

		_name = map.getStringAt(nameOffset);
	}

	private int read3ByteValue(BinaryReader reader) throws IOException {
		int value1 = reader.readNextByte() & 0xff;
		int value2 = reader.readNextByte() & 0xff;
		int value3 = reader.readNextByte() & 0xff;
		if (reader.isLittleEndian()) {
			return (value3 << 16) | (value2 << 8) | value1;
		}
		return (value1 << 16) | (value2 << 8) | value3;
	}

	/**
	 * Returns the resource ID.
	 * @return the resource ID
	 */
	public short getID() {
		return id;
	}

	public String getName() {
		return _name;
	}

	/**
	 * Returns the offset from the beginning of the resource
	 * name list to resource name.
	 * @return the offset to the resource name
	 */
	public short getNameOffset() {
		return nameOffset;
	}

	/**
	 * Returns the resource attributes.
	 * @return the resource attributes
	 */
	public byte getAttributes() {
		return attributes;
	}

	/**
	 * Returns the offset from the beginning of the
	 * resource data to the data for this resource.
	 * @return the offset to the resource data
	 */
	public int getDataOffset() {
		return dataOffset;
	}

	/**
	 * Returns the resource handle.
	 * This field is reserved.
	 * @return the resource handle
	 */
	public int getHandle() {
		return handle;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = StructConverterUtil.parseName(ReferenceListEntry.class);
		Structure struct = new StructureDataType(name, 0);
		struct.add(WORD, "id", null);
		struct.add(WORD, "nameOffset", null);
		struct.add(BYTE, "attributes", null);
		struct.add(new UnsignedInteger3DataType(), "dataOffset", null);
		struct.add(DWORD, "handle", null);
		return struct;
	}
}
