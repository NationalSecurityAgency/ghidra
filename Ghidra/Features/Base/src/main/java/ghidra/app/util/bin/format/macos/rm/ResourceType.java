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
import java.util.ArrayList;
import java.util.List;

public class ResourceType implements StructConverter {
	private int type;
	private byte [] _typeBytes;
	private short numberOfResources;//minus 1
	private short offsetToReferenceList;

	private List<ReferenceListEntry> _referenceList = new ArrayList<ReferenceListEntry>();
	private Object _resourceObject;

	ResourceType(BinaryReader reader, ResourceHeader header, ResourceMap map, long resourceTypeListStartIndex) throws IOException {
		type = reader.peekNextInt();
		_typeBytes = reader.readNextByteArray(4);
		numberOfResources = reader.readNextShort();
		offsetToReferenceList = reader.readNextShort();

		parseReferenceList(reader, map);

		_resourceObject = ResourceTypeFactory.getResourceObject(reader, header, this);
	}

	private void parseReferenceList(BinaryReader reader, ResourceMap map) throws IOException {
		long referenceListStartIndex = map.getMapStartIndex() + map.getResourceTypeListOffset() + offsetToReferenceList;

		long oldIndex = reader.getPointerIndex();
		reader.setPointerIndex(referenceListStartIndex);
		try {
			for (int i = 0 ; i < numberOfResources + 1 ; ++i) {
				_referenceList.add(new ReferenceListEntry(reader, map));
			}
		}
		finally {
			reader.setPointerIndex(oldIndex);
		}
	}

	public Object getResourceObject() {
		return _resourceObject;
	}

	/**
	 * Returns the resource type.
	 * @return the resource type
	 */
	public int getType() {
		return type;
	}

	public String getTypeAsString() {
		if (isAscii()) {
			return new String(_typeBytes);
		}
		return "0x"+Integer.toHexString(type);
	}

	/**
	 * Returns the number of resources of this type
	 * in map minus 1.
	 * @return the number of resources
	 */
	public short getNumberOfResources() {
		return numberOfResources;
	}

	/**
	 * Returns the offset from the beginning of the 
	 * resource type list to reference list for this type.
	 * @return the offset to reference list
	 */
	public short getOffsetToReferenceList() {
		return offsetToReferenceList;
	}

	public List<ReferenceListEntry> getReferenceList() {
		return _referenceList;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = StructConverterUtil.parseName(ResourceType.class);
		Structure struct = new StructureDataType(name, 0);
		if (isAscii()) {
			struct.add(new StringDataType(), 4, "type", null);
		}
		else {
			struct.add(DWORD, "type", null);
		}
		struct.add(WORD, "numberOfResources", null);
		struct.add(WORD, "offsetToReferenceList", null);
		return struct;
	}

	private boolean isAscii() {
		for (byte b : _typeBytes) {
			if (b < ' ' || b > 126) {
				return false;
			}
		}
		return true;
	}
}
