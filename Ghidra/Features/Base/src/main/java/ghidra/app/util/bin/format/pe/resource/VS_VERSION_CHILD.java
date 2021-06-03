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
package ghidra.app.util.bin.format.pe.resource;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * A class to represent the VS_VERSION_CHILD data structure which generally corresponds 
 * to either StringFileInfo or VarFileInfo.  Only a single instance of each childName
 * is expected.
 */
public class VS_VERSION_CHILD implements StructConverter {
	private String parentName;
	private long relativeOffset; // offset relative to start of parent structure
	private String childName;
	private short childSize;
	private short childValueSize;
	private short childValueType;

	private String childDataType;

	private int valueAlignment;
	private String childValue; // will be null if this has children

	private ArrayList<VS_VERSION_CHILD> children;

	VS_VERSION_CHILD(FactoryBundledWithBinaryReader reader, long relativeOffset, String parentName,
			HashMap<String, String> valueMap) throws IOException {
		this.relativeOffset = relativeOffset;
		this.parentName = parentName;
		long origIndex = reader.getPointerIndex();

		childSize = reader.readNextShort();

		if (childSize == 0) {
			return;
		}

		childValueSize = reader.readNextShort();
		childValueType = reader.readNextShort();

		childName = reader.readNextUnicodeString();

		valueAlignment = reader.align(4);

		boolean hasChildren = false;
		if (parentName == null) {
			childDataType = childName;
			hasChildren = true;
		}
		else if ("StringFileInfo".equals(parentName)) {
			childDataType = "StringTable";
			hasChildren = true;
		}
		else if ("VarFileInfo".equals(parentName)) {
			childDataType = "Var";
			if (childValueSize > 0) {
				childValue = Integer.toHexString(reader.readNextInt());
			}
		}
		else if ("StringTable".equals(parentName)) {
			// Should be called "String" but this may conflict with other String types
			// Also, we have seen some PE's where the childValueType of this is 0, so we can't
			// rely on that to know if we should read an integer or a string.  This field is 
			// always a string regardless of the specified type.
			childDataType = "StringInfo";
			if (childValueSize > 0) {
				childValue = reader.readNextUnicodeString();
			}
		}


		if (hasChildren) {
			while (reader.getPointerIndex() < origIndex + childSize) {
				VS_VERSION_CHILD child = new VS_VERSION_CHILD(reader,
					reader.getPointerIndex() - origIndex, childDataType, valueMap);
				if (children == null) {
					children = new ArrayList<VS_VERSION_CHILD>();
				}
				children.add(child);
			}
		}
		else {
			if (childValueSize > 0 && childValue != null) {
				valueMap.put(childName, childValue);
			}
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException {
		if (childName == null || childDataType == null) {
			return null;
		}
		StructureDataType struct = new StructureDataType(childDataType, 0);
		struct.add(WORD, "wLength", null);
		struct.add(WORD, "wValueLength", null);
		struct.add(WORD, "wType", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}

	/**
	 * Returns the array of children
	 * @return the array of children
	 */
	public VS_VERSION_CHILD[] getChildren() {
		VS_VERSION_CHILD[] arr = new VS_VERSION_CHILD[children.size()];
		children.toArray(arr);
		return arr;
	}

	/**
	 * Return structure offset relative to parent structure start
	 * @return relative offset
	 */
	public long getRelativeOffset() {
		return relativeOffset;
	}

	/**
	 * Returns the version child name.
	 * @return the version child name
	 */
	public String getChildName() {
		return childName;
	}

	/**
	 * Returns the version child size.
	 * @return the version child size
	 */
	public short getChildSize() {
		return childSize;
	}

	/**
	 * Return value offset relative to parent structure start.
	 * @return relative value offset or 0 if no value exists
	 */
	public long getValueRelativeOffset() {
		if (childValue == null) {
			return 0;
		}
		return ((childName.length() + 1) * 2) + valueAlignment + 6;
	}

	/**
	 * Return unicode name string offset relative to parent structure start
	 * @return relative name offset or 0 if data type is unknown
	 */
	public long getNameRelativeOffset() {
		if (childSize == 0) {
			return 0;
		}
		return 6;
	}

	/**
	 * @return true if value is unicode string
	 */
	public boolean valueIsUnicodeString() {
		return childValue != null && "StringInfo".equals(childDataType);
	}

	/**
	 * @return true if value is 4-byte integer value in memory 
	 * while string value return by {@link DataType#getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 * DataType.getValue(MemBuffer, Settings, int)} is a numeric hex string.
	 */
	public boolean valueIsDWord() {
		return childValue != null && "Var".equals(childDataType);
	}

	/**
	 * @return true if this child has children
	 */
	public boolean hasChildren() {
		return children != null;
	}

}
