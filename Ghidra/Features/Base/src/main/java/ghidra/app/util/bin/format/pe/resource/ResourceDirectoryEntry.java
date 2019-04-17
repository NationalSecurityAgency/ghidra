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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.ResourceDataDirectory;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * <pre>
 * typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
 *     union {
 *         struct {
 *             DWORD NameOffset:31;
 *             DWORD NameIsString:1;
 *         };
 *         DWORD   Name;
 *         WORD    Id;
 *     };
 *     union {
 *         DWORD   OffsetToData;
 *         struct {
 *             DWORD   OffsetToDirectory:31;
 *             DWORD   DataIsDirectory:1;
 *         };
 *     };
 * };
 * </pre>
 */
public class ResourceDirectoryEntry implements StructConverter {
	private final static String NAME = "IMAGE_RESOURCE_DIRECTORY_ENTRY";
	public final static int SIZEOF = 8;

	private boolean isNameEntry;
	private boolean isFirstLevel;
	private ResourceDirectoryStringU dirString;
	private ResourceDirectory subDirectory;
	private ResourceDataEntry data;

	private int nameOffset;
	private boolean nameIsString;
	private int name;
	private int id;
	private int offsetToData;
	private int offsetToDirectory;
	private boolean dataIsDirectory;

	private boolean isValid;

	/**
	 * Constructor.
	 * @param reader the binary reader
	 * @param index the index where this directory begins
	 */
	public ResourceDirectoryEntry(FactoryBundledWithBinaryReader reader, int index,
			int resourceBase, boolean isNameEntry, boolean isFirstLevel, NTHeader ntHeader)
			throws IOException {

		this.isNameEntry = isNameEntry;
		this.isFirstLevel = isFirstLevel;

		int irde1 = reader.readInt(index);
		int irde2 = reader.readInt(index + BinaryReader.SIZEOF_INT);

		nameOffset = irde1 & 0x7FFFFFFF;
		nameIsString = (irde1 & 0x80000000) != 0;
		if (nameOffset < 0) {
			Msg.error(this, "Invalid nameOffset " + nameOffset);
			return;
		}
		name = irde1;
		id = irde1 & 0xFFFF;

		offsetToData = irde2;
		offsetToDirectory = irde2 & 0x7FFFFFFF;
		dataIsDirectory = (irde2 & 0x80000000) != 0;

		if (nameIsString) {
			int nameptr = nameOffset + resourceBase;
			if (ntHeader.checkRVA(nameptr) || (0 < nameptr && nameptr < reader.length())) {
				dirString = new ResourceDirectoryStringU(reader, nameptr);
			}
			else {
				Msg.error(this, "Invalid nameOffset " + Integer.toHexString(nameOffset));
				return;
			}
		}
		else { // name is ID

		}
		if (dataIsDirectory) {
			int dirptr = offsetToDirectory + resourceBase;
			if (ntHeader.checkRVA(dirptr) || (0 < dirptr && dirptr < reader.length())) {
				subDirectory = new ResourceDirectory(reader, dirptr, resourceBase, false, ntHeader);
			}
			else {
				Msg.error(this,
					"Invalid offsetToDirectory " + Integer.toHexString(offsetToDirectory));
				return;
			}
		}
		else {
			int dataptr = offsetToData + resourceBase;
			if (ntHeader.checkRVA(dataptr) || (0 < dataptr && dataptr < reader.length())) {
				data = new ResourceDataEntry(reader, dataptr);
			}
			else {
				Msg.error(this, "Invalid offsetToData " + Integer.toHexString(offsetToData));
				return;
			}
		}

		isValid = true;
	}

	public List<ResourceInfo> getResources(int level) {
		ArrayList<ResourceInfo> resources = new ArrayList<ResourceInfo>();

		if (data != null) {
			resources.add(new ResourceInfo(data.getOffsetToData(), toString(), data.getSize()));
		}
		if (subDirectory != null) {
			List<ResourceDirectoryEntry> entries = subDirectory.getEntries();
			for (ResourceDirectoryEntry entry : entries) {
				List<ResourceInfo> entryResources = entry.getResources(level + 1);
				for (ResourceInfo info : entryResources) {
					resources.add(info);
					info.setName(toString() + "_" + info.getName());
					if (!isNameEntry) {
						if (level == 0) {
							info.setTypeID(id);
						}
						else if (level == 1) {
							info.setID(id);
						}
					}
				}
			}
		}
		return resources;
	}

	/**
	 * Returns true if the parent resource directory is named,
	 * false indicates an ID.
	 */
	public boolean isNameEntry() {
		return isNameEntry;
	}

	public ResourceDirectoryStringU getDirectoryString() {
		return dirString;
	}

	public ResourceDataEntry getData() {
		return data;
	}

	public ResourceDirectory getSubDirectory() {
		return subDirectory;
	}

	@Override
	public String toString() {
		if (isNameEntry && dirString != null) {
			return dirString.getNameString();
		}
		if (!isNameEntry && isFirstLevel && id <= ResourceDataDirectory.RT_MANIFEST) {
			return ResourceDataDirectory.PREDEFINED_RESOURCE_NAMES[id];
		}
		return Integer.toHexString(id);
	}

	/**
	 * Returns the offset to the name of this resource.
	 * @return the offset to the name of this resource
	 * @see #getName()
	 */
	public int getNameOffset() {
		return nameOffset;
	}

	/**
	 * Returns the ID of the name of this resource.
	 * @return the ID of the name of this resource
	 * @see #getName()
	 */
	public boolean getNameIsString() {
		return nameIsString;
	}

	/**
	 * @return either an integer ID or a pointer to a structure that contains a string name
	 */
	public int getName() {
		return name;
	}

	/**
	 * Returns a resource ID.
	 * @return a resource ID
	 * @see #getName()
	 */
	public int getId() {
		return id;
	}

	/**
	 * @return either an offset to another resource directory 
	 *         or a pointer to information about a specific resource instance
	 */
	public int getOffsetToData() {
		return offsetToData;
	}

	/**
	 * Returns an offset to another resource directory.
	 * @return an offset to another resource directory
	 * @see #getOffsetToData()
	 */
	public int getOffsetToDirectory() {
		return offsetToDirectory;
	}

	/**
	 * Returns a pointer to information about a specific resource instance.
	 * @return a pointer to information about a specific resource instance
	 * @see #getOffsetToData()
	 */
	public boolean getDataIsDirectory() {
		return dataIsDirectory;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType nameStruct = new StructureDataType(NAME + "_" + "NameStruct", 0);
		nameStruct.add(DWORD, "NameOffset", null);
		nameStruct.add(DWORD, "NameIsString", null);
		nameStruct.setCategoryPath(new CategoryPath("/PE"));

		UnionDataType union1 = new UnionDataType(NAME + "_" + "NameUnion");
		union1.add(nameStruct, nameStruct.getName(), null);
		union1.add(DWORD, "Name", null);
		union1.add(WORD, "Id", null);
		union1.setCategoryPath(new CategoryPath("/PE"));

		StructureDataType offsetStruct = new StructureDataType(NAME + "_" + "DirectoryStruct", 0);
		offsetStruct.add(DWORD, "OffsetToDirectory", null);
		offsetStruct.add(DWORD, "DataIsDirectory", null);

		UnionDataType union2 = new UnionDataType(NAME + "_" + "DirectoryUnion");
		union2.add(DWORD, "OffsetToData", null);
		union2.add(offsetStruct, offsetStruct.getName(), null);

		UnionDataType union3 = new UnionDataType(NAME);
		union3.add(union1, "NameUnion", null);
		union3.add(union2, "DirectoryUnion", null);

		union3.setCategoryPath(new CategoryPath("/PE"));
		return union3;
	}

	public boolean isValid() {
		return isValid;
	}

}
