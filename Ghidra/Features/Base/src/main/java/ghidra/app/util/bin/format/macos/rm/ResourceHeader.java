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
import ghidra.app.util.bin.format.macos.asd.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class ResourceHeader extends Entry implements StructConverter {
	private int resourceDataOffset;
	private int resourceMapOffset;
	private int resourceDataLength;
	private int resourceMapLength;

	private ResourceMap _map;

	public ResourceHeader(ByteProvider provider) throws IOException {
		this(new BinaryReader(provider, false), 
			 new EntryDescriptor(EntryDescriptorID.ENTRY_RESOURCE_FORK, 0, (int)provider.length()));
	}

	public ResourceHeader(BinaryReader reader, EntryDescriptor entry) throws IOException {
		this(reader, entry, false);
	}

	ResourceHeader(BinaryReader reader, EntryDescriptor entry, boolean onlyDoShallowParsing) throws IOException {
		super(entry);

		long beginningOfResourceFork = reader.getPointerIndex();

		resourceDataOffset = reader.readNextInt();
		resourceMapOffset  = reader.readNextInt();
		resourceDataLength = reader.readNextInt();
		resourceMapLength  = reader.readNextInt();

		if (onlyDoShallowParsing) {
			return;
		}

		long oldIndex = reader.getPointerIndex();
		try {
			reader.setPointerIndex(beginningOfResourceFork + resourceMapOffset);
			_map = new ResourceMap(reader, this);
		}
		finally {
			reader.setPointerIndex(oldIndex);
		}
	}

	/**
	 * Returns the offset from the beginning of resource fork
	 * to resource map.
	 * @return offset to resource map
	 */
	public int getResourceMapOffset() {
		return resourceMapOffset;
	}

	/**
	 * Returns the length of the resource map.
	 * @return the length of the resource map
	 */
	public int getResourceMapLength() {
		return resourceMapLength;
	}

	/**
	 * Returns the offset from the beginning of resource fork
	 * to resource data.
	 * @return offset to resource data
	 */
	public int getResourceDataOffset() {
		return resourceDataOffset;
	}

	/**
	 * Returns the length of the resource data.
	 * @return the length of the resource data
	 */
	public int getResourceDataLength() {
		return resourceDataLength;
	}

	public ResourceMap getMap() {
		return _map;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(ResourceHeader.class);
	}
}
