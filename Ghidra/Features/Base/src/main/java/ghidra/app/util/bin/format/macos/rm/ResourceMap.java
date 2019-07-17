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
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.*;

public class ResourceMap implements StructConverter {
	private ResourceHeader copy;
	private int handleToNextResourceMap;
	private short fileReferenceNumber;
	private short resourceForkAttributes;
	private short resourceTypeListOffset;//from beginning of map
	private short resourceNameListOffset;//from beginning of map
	private short numberOfTypes;//minus 1

	private long _mapStartIndex;
	private List<ResourceType> _resourceTypeList = new ArrayList<ResourceType>();
	private List<ReferenceListEntry> _referenceEntryList = new ArrayList<ReferenceListEntry>();
	private Map<Short, String> _resourceNameMap = new HashMap<Short, String>();

	ResourceMap(BinaryReader reader, ResourceHeader header) throws IOException {
		_mapStartIndex = reader.getPointerIndex();

		copy = new ResourceHeader(reader, header.getEntryDescriptor(), true);

		handleToNextResourceMap = reader.readNextInt();
		fileReferenceNumber     = reader.readNextShort();
		resourceForkAttributes  = reader.readNextShort();
		resourceTypeListOffset  = reader.readNextShort();
		resourceNameListOffset  = reader.readNextShort();
		numberOfTypes           = reader.readNextShort();

		long oldIndex = reader.getPointerIndex();
		try {
			parseResourceNameList(reader);
			parseResourceTypeList(reader, header);
		}
		finally {
			reader.setPointerIndex(oldIndex);
		}
	}

	private void parseResourceTypeList(BinaryReader reader, ResourceHeader header) throws IOException {
		long resourceTypeListStart = _mapStartIndex + resourceTypeListOffset + 2;/*TODO*/
		reader.setPointerIndex(resourceTypeListStart);
		for (int i = 0 ; i < numberOfTypes + 1 ; ++i) {
			_resourceTypeList.add(new ResourceType(reader, header, this, resourceTypeListStart));
		}
	}

	private void parseResourceNameList(BinaryReader reader) throws IOException {
		long start = _mapStartIndex + resourceNameListOffset;
		reader.setPointerIndex(_mapStartIndex + resourceNameListOffset);
		while (reader.getPointerIndex() < reader.length()) {
			long offset = reader.getPointerIndex();
			int length = reader.readNextByte() & 0xff;
			String name = reader.readNextAsciiString(length);
			_resourceNameMap.put((short)(offset - start), name);
		}
	}

	public ResourceHeader getCopy() {
		return copy;
	}

	public int getHandleToNextResourceMap() {
		return handleToNextResourceMap;
	}

	public short getFileReferenceNumber() {
		return fileReferenceNumber;
	}

	public short getResourceForkAttributes() {
		return resourceForkAttributes;
	}

	public short getResourceTypeListOffset() {
		return resourceTypeListOffset;
	}

	public short getResourceNameListOffset() {
		return resourceNameListOffset;
	}

	public short getNumberOfTypes() {
		return numberOfTypes;
	}

	public List<ResourceType> getResourceTypeList() {
		return _resourceTypeList;
	}

	public List<ReferenceListEntry> getReferenceEntryList() {
		return _referenceEntryList;
	}

	public String getStringAt(short offset) {
		if (offset == -1) {
			return null;
		}
		return _resourceNameMap.get(offset);
	}

	public long getMapStartIndex() {
		return _mapStartIndex;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(ResourceMap.class);
	}
}
