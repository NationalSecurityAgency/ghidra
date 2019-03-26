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
package ghidra.app.util.datatype.microsoft;

import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.List;

public class GroupIconResourceDataType extends DynamicDataType {

	public GroupIconResourceDataType() {
		this(null, "GroupIconResource", null);
	}

	public GroupIconResourceDataType(DataTypeManager dtm) {
		this(null, "GroupIconResource", dtm);
	}

	protected GroupIconResourceDataType(CategoryPath path, String name, DataTypeManager dtm) {
		super(path, name, dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new GroupIconResourceDataType(dtm);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "GroupIconRes";
	}

	@Override
	public String getDescription() {
		return "GroupIcon stored as a Resource";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return "GroupIcon";
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "<GroupIcon-Resource>";
	}

	@Override
	protected DataTypeComponent[] getAllComponents(MemBuffer buf) {

		List<DataTypeComponent> comps = new ArrayList<>();
		MemBuffer memBuffer = buf;
		int structureOffset = 0;
		int numIconDirEntries;

		try {
			//first add the main GroupIcon header GRPIICONDIR			
			comps.add(new ReadOnlyDataTypeComponent(GroupIconHeaderStructure(), this, 6,
				comps.size(), structureOffset, "GroupIcon Header", null));

			//get the number of Icon Directory Entry Structures from the idCount member of the header structure 
			numIconDirEntries = memBuffer.getShort(structureOffset + 4);

			//increment the offset by the header size
			structureOffset += 6;

			//add each Icon Directory Entry structure and increment the offset by the structure size
			for (int i = 0; i < numIconDirEntries; i++) {
				comps.add(new ReadOnlyDataTypeComponent(GroupIconDirEntryStructure(), this, 14,
					comps.size(), structureOffset, "GroupIcon Entry", null));
				structureOffset += 14;
			}

		}
		catch (MemoryAccessException e1) {
			Msg.debug(this, "Error applying GroupIcon Resource Data Type.");
		}

		DataTypeComponent[] result = comps.toArray(new DataTypeComponent[comps.size()]);
		return result;
	}

	//This is the first thing in a Group Icon Resource
	private StructureDataType GroupIconHeaderStructure() {

		StructureDataType struct = new StructureDataType("GRPICONDIR", 0);

		struct.add(WordDataType.dataType, "idReserved", null);
		struct.add(WordDataType.dataType, "idType", null);
		struct.add(WordDataType.dataType, "idCount", null);
		struct.setCategoryPath(new CategoryPath("/PE"));

		return struct;
	}

	//These structures follow the main header structure - the number of them is defined in the main header
	private StructureDataType GroupIconDirEntryStructure() {

		StructureDataType struct = new StructureDataType("GRPICONDIRENTRY", 0);

		struct.add(ByteDataType.dataType, "bWidth", null);
		struct.add(ByteDataType.dataType, "bHeight", null);
		struct.add(ByteDataType.dataType, "bColorCount", null);
		struct.add(ByteDataType.dataType, "bReserved", null);
		struct.add(WordDataType.dataType, "wPlanes", null);
		struct.add(WordDataType.dataType, "wBitCount", null);
		struct.add(DWordDataType.dataType, "dwBytesInResource", null);
		struct.add(WordDataType.dataType, "nId", null);

		struct.setCategoryPath(new CategoryPath("/PE"));

		return struct;
	}

}
