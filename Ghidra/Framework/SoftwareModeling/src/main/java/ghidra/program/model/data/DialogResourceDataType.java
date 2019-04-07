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
package ghidra.program.model.data;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassTranslator;
import ghidra.util.exception.DuplicateNameException;

import java.util.*;

public class DialogResourceDataType extends DynamicDataType {

	private static byte DS_SETFONT = 0x40;

	private static Map<Integer, String> itemTypeMap = new HashMap<>();
	static {
		itemTypeMap.put(0x0080, "Button");
		itemTypeMap.put(0x0081, "Edit");
		itemTypeMap.put(0x0082, "Static");
		itemTypeMap.put(0x0083, "List Box");
		itemTypeMap.put(0x0084, "Scoll Bar");
		itemTypeMap.put(0x0085, "Combo Box");
	}

	static {
		ClassTranslator.put("ghidra.app.plugin.prototype.data.DialogResourceDataType",
			DialogResourceDataType.class.getName());
	}

	public DialogResourceDataType() {
		super(null, "DialogResource", null);
	}

	public DialogResourceDataType(DataTypeManager dtm) {
		super(null, "DialogResource", dtm);
	}

	@Override
	public String getDescription() {
		return "Dialog stored as a Resource";
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "DialogRes";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int len) {
		return "Dialog";
	}

	//Dialog resource contains the following:
	//   fixed length DLGTEMPLATE structure followed by the following three arrays and possibly a word and another array
	//   variable length menu array for dialog box (word aligned) 0x0000=no menu in dialog, 0xFFFF = one additional element - the ordinal of the menu resource, else null term. unicode string
	//   variable length class array for dialog box (word aligned) 0x0000=use predefined dialog box class, 0xFFFF = one additional element - the ordinal of predefined system window class, else null term. unicode string
	//   variable length title array for dialog box (word aligned) 0x0000=no title, else null term. unicode string
	//   if DS_SETFONT (0x40) is specified by the style member then these are followed by
	//       word - font size
	//       variable length font typeface array (word aligned)
	//   Some number (defined by cedit value) of fixed length DLGITEMTEMPLATE structures (each must be on align 4 - one for each dialog box control item) each followed by the following three arrays - DWORD aligned
	//   variable length class array for item (word aligned) 0xFFFF = one additional element - the ordinal of predefined system class, else  null term. unicode string
	//				Ordinal values: 0x0080 Button, 0x0081 Edit, 0x0082 Static, 0x0083 List Box, 0x0084 Scroll Bar, 0x0085 Combo Box
	//   variable length title''' array for item (word aligned) 0xFFFF = one additional element - the ordinal of resource, such as an icon, else  null term. unicode string
	//   variable length data array for the item (word aligned) 0x0000 = no data, else first word is size including size word of the data array

	@Override
	protected DataTypeComponent[] getAllComponents(MemBuffer mbIn) {
		List<DataTypeComponent> comps = new ArrayList<>();
		int tempOffset = 0;
		MemBuffer memBuffer = mbIn;

		try {
			tempOffset = addDlgTemplateStructure(memBuffer, comps, tempOffset);

			tempOffset = addDialogMenuArray(memBuffer, comps, tempOffset);

			tempOffset = addDialogClassArray(memBuffer, comps, tempOffset);

			tempOffset = addDialogTitleArray(memBuffer, comps, tempOffset);

			//Check to see if extra font size and array info after three dialog items
			//will only be there if DS_SETFONT mask is set at offset 0 of DLGTEMPLATE
			byte getStyle = memBuffer.getByte(0);
			if ((getStyle & DS_SETFONT) > 0) {
				tempOffset = addDialogFontSizeAndArray(memBuffer, comps, tempOffset);
			}

			//get cdit value at offset 8 of DLGTEMPLATE
			//this determines how many DLGITEMTEMPLATE items their are
			short numComponents = memBuffer.getShort(8);

			//loop over DLGITEMTEMPLATES and add them
			for (int i = 0; i < numComponents; i++) {

				tempOffset = addDlgItemStructure(memBuffer, comps, tempOffset);

				tempOffset = addItemClassArray(memBuffer, comps, tempOffset);

				tempOffset = addItemTitleArray(memBuffer, comps, tempOffset);

				tempOffset = addItemCreationData(memBuffer, comps, tempOffset);
			}
		}
		catch (MemoryAccessException e) {
			Msg.error(this, "buffer error: " + e.getMessage(), e);
		}

		DataTypeComponent[] result = comps.toArray(new DataTypeComponent[comps.size()]);
		return result;
	}

	//adds initial DLGITEMTEMPLATES structure
	private int addDlgTemplateStructure(MemBuffer memBuffer, List<DataTypeComponent> comps,
			int tempOffset) {

		tempOffset =
			addComp(dlgTemplateStructure(), 18, "Dialog Template Structure",
				memBuffer.getAddress(), comps, tempOffset);

		return tempOffset;
	}

	//adds Dialog Menu array - the 1st component after the initial DLGTEMPLATE structure
	private int addDialogMenuArray(MemBuffer memBuffer, List<DataTypeComponent> comps,
			int tempOffset) throws MemoryAccessException {

		short dialogMenuInfo = memBuffer.getShort(tempOffset);
		if (dialogMenuInfo == 0x0000) { //if 0x0000 - no menu
			tempOffset =
				addComp(createArrayOfShorts(1), 2, "Dialog Menu",
					memBuffer.getAddress().add(tempOffset), comps, tempOffset);
		}
		//if 0xFFFF - one more item that is resource number of the menu
		else if (dialogMenuInfo == 0xFFFF) {
			tempOffset =
				addComp(createArrayOfShorts(2), 4, "Dialog Menu",
					memBuffer.getAddress().add(tempOffset), comps, tempOffset);
		}
		//array is unicode name of menu in executable file
		else {
			tempOffset = addUnicodeString(memBuffer, comps, tempOffset, "Dialog Menu");
		}
		return tempOffset;
	}

	//adds Dialog Class array - the 2nd component after the initial DLGTEMPLATE structure
	private int addDialogClassArray(MemBuffer memBuffer, List<DataTypeComponent> comps,
			int tempOffset) throws MemoryAccessException {

		short dialogClassInfo = memBuffer.getShort(tempOffset);

		//if 0x0000 - use predefined class
		if (dialogClassInfo == 0x0000) {
			tempOffset =
				addComp(createArrayOfShorts(1), 2, "Dialog Class",
					memBuffer.getAddress().add(tempOffset), comps, tempOffset);
		}
		//if 0xFFFF - one more item that is ordinal value of system window class
		else if (dialogClassInfo == 0xFFFF) {
			tempOffset =
				addComp(createArrayOfShorts(2), 4, "Dialog Class",
					memBuffer.getAddress().add(tempOffset), comps, tempOffset);
		}
		//array is unicode name of menu in executable file
		else {
			tempOffset = addUnicodeString(memBuffer, comps, tempOffset, "Dialog Class");
		}
		return tempOffset;
	}

	//adds Dialog Title array - the 3rd component after the DLGTEMPLATE structure
	private int addDialogTitleArray(MemBuffer memBuffer, List<DataTypeComponent> comps,
			int tempOffset) throws MemoryAccessException {
		//add Dialog Title array
		short dialogTitleInfo = memBuffer.getShort(tempOffset);
		//if 0x0000 - Dialog has no title
		if (dialogTitleInfo == 0x0000) {
			tempOffset =
				addComp(createArrayOfShorts(1), 2, "Dialog Title",
					memBuffer.getAddress().add(tempOffset), comps, tempOffset);
		}
		//array is unicode name of menu in executable file
		else {
			tempOffset = addUnicodeString(memBuffer, comps, tempOffset, "Dialog Title");
		}
		return tempOffset;
	}

	//adds Dialog font size and font array - the OPTIONAL 4th and 5th components after the DLGTEMPLATE structure
	private int addDialogFontSizeAndArray(MemBuffer memBuffer, List<DataTypeComponent> comps,
			int tempOffset) {
		//add Dialog Font size
		tempOffset =
			addComp(new ShortDataType(), 2, "Dialog Font Size",
				memBuffer.getAddress().add(tempOffset), comps, tempOffset);

		//add Dialog Font Style array
		tempOffset = addUnicodeString(memBuffer, comps, tempOffset, "Dialog Font Typeface");
		return tempOffset;
	}

	//adds DLGITEMTEMPLATES structure - must start on 4 byte alignment
	//the number of these is defined by the cdit value in the DLGTEMPLATE structure
	private int addDlgItemStructure(MemBuffer memBuffer, List<DataTypeComponent> comps,
			int tempOffset) {

		if ((memBuffer.getAddress().add(tempOffset).getOffset() % 4) != 0) {
			tempOffset =
				addComp(new AlignmentDataType(), 2, "Alignment",
					memBuffer.getAddress().add(tempOffset), comps, tempOffset);
		}
		tempOffset =
			addComp(dlgItemTemplateStructure(), 18, "Dialog Item Structure",
				memBuffer.getAddress().add(tempOffset), comps, tempOffset);

		return tempOffset;
	}

	//adds Item class array - 1st after component after each DLGITEMTEMPLATE structure
	private int addItemClassArray(MemBuffer memBuffer, List<DataTypeComponent> comps, int tempOffset)
			throws MemoryAccessException {

		short itemClassInfo = memBuffer.getShort(tempOffset);
		if ((itemClassInfo & 0xffff) == 0xffff) {
			short classType = memBuffer.getShort(tempOffset + 2);
			tempOffset =
				addComp(createArrayOfShorts(2), 4, "Item Class Type or Name" + "(" +
					getItemType(Integer.valueOf(classType)) + ")",
					memBuffer.getAddress().add(tempOffset), comps, tempOffset);
		}
		else {
			tempOffset = addUnicodeString(memBuffer, comps, tempOffset, "Item Class Type or Name");
		}
		return tempOffset;
	}

	//adds Item title array - 2nd after each DLGITEMTEMPLATE structure
	private int addItemTitleArray(MemBuffer memBuffer, List<DataTypeComponent> comps, int tempOffset)
			throws MemoryAccessException {

		short itemTitleInfo = memBuffer.getShort(tempOffset);
		if ((itemTitleInfo & 0xffff) == 0xffff) {
			tempOffset =
				addComp(createArrayOfShorts(2), 4, "Item Title or Resource ID",
					memBuffer.getAddress().add(tempOffset), comps, tempOffset);
		}
		else {
			tempOffset =
				addUnicodeString(memBuffer, comps, tempOffset, "Item Title or Resource ID");
		}
		return tempOffset;
	}

	//adds Item data component - 3rd after each DLGITEMTEMPLATE structure
	private int addItemCreationData(MemBuffer memBuffer, List<DataTypeComponent> comps,
			int tempOffset) throws MemoryAccessException {

		short itemDataLength = memBuffer.getShort(tempOffset);
		if (itemDataLength == 0x0000) {
			tempOffset =
				addComp(createArrayOfShorts(1), 2, "Item Data",
					memBuffer.getAddress().add(tempOffset), comps, tempOffset);
		}
		else {
			tempOffset =
				addComp(new ArrayDataType(ByteDataType.dataType, itemDataLength, 1),
					itemDataLength, "Item Data", memBuffer.getAddress().add(tempOffset), comps,
					tempOffset);
		}
		return tempOffset;
	}

	//This is always the first structure in the dialog resource
	private StructureDataType dlgTemplateStructure() {
		StructureDataType struct = new StructureDataType("DLGTEMPLATE", 0);

		struct.add(DWordDataType.dataType);
		struct.add(DWordDataType.dataType);
		struct.add(WordDataType.dataType);
		struct.add(ShortDataType.dataType);
		struct.add(ShortDataType.dataType);
		struct.add(ShortDataType.dataType);
		struct.add(ShortDataType.dataType);

		try {
			struct.getComponent(0).setFieldName("style");
			struct.getComponent(1).setFieldName("dwExtendedStyle");
			struct.getComponent(2).setFieldName("cdit");
			struct.getComponent(3).setFieldName("x");
			struct.getComponent(4).setFieldName("y");
			struct.getComponent(5).setFieldName("cx");
			struct.getComponent(6).setFieldName("cy");
		}
		catch (DuplicateNameException e) {
			Msg.debug(this, "Unexpected exception building DLGTEMPLATE", e);
		}
		struct.getComponent(0).setComment("style of dialog box");
		struct.getComponent(1).setComment("extended styles for a window");
		struct.getComponent(2).setComment("number of items in dialog box");
		struct.getComponent(3).setComment("x-coordinate of upper-left corner of dialog");
		struct.getComponent(4).setComment("y-coordinate of upper-left corner of dialog");
		struct.getComponent(5).setComment("width of dialog box");
		struct.getComponent(6).setComment("height of dialog box");

		return struct;
	}

	//Each control item has one of these structures
	private StructureDataType dlgItemTemplateStructure() {
		StructureDataType struct = new StructureDataType("DLGITEMTEMPLATE", 0);

		try {
			struct.add(DWordDataType.dataType);
			struct.add(DWordDataType.dataType);
			struct.add(ShortDataType.dataType);
			struct.add(ShortDataType.dataType);
			struct.add(ShortDataType.dataType);
			struct.add(ShortDataType.dataType);
			struct.add(WordDataType.dataType);

			struct.getComponent(0).setFieldName("style");
			struct.getComponent(1).setFieldName("dwExtendedStyle");
			struct.getComponent(2).setFieldName("x");
			struct.getComponent(3).setFieldName("y");
			struct.getComponent(4).setFieldName("cx");
			struct.getComponent(5).setFieldName("cy");
			struct.getComponent(6).setFieldName("id");
		}
		catch (DuplicateNameException e) {
			Msg.debug(this, "Unexpected exception building DLGITEMTEMPLATE", e);
		}

		struct.getComponent(0).setComment("style of control");
		struct.getComponent(1).setComment("extended styles for a window");
		struct.getComponent(2).setComment("x-coordinate of upper-left corner of control");
		struct.getComponent(3).setComment("y-coordinate of upper-left corner of control");
		struct.getComponent(4).setComment("width of control");
		struct.getComponent(5).setComment("height of control");
		struct.getComponent(6).setComment("control identifier");

		return struct;
	}

	//returns the name of the predefined item class type for an item
	public String getItemType(Integer value) {
		return itemTypeMap.get(value);
	}

	private int addUnicodeString(MemBuffer memBuffer, List<DataTypeComponent> comps,
			int tempOffset, String title) {

		byte[] tempBytes = new byte[1024];
		memBuffer.getBytes(tempBytes, tempOffset);
		int strLength = findUnicodeLength(tempBytes);
		if (strLength >= 2) {
			tempOffset =
				addComp(UnicodeDataType.dataType, strLength, title,
					memBuffer.getAddress().add(tempOffset), comps, tempOffset);
		}

		return tempOffset;
	}

	static int findUnicodeLength(byte[] byteArray) {

		int i = 0;

		while (i <= byteArray.length) {
			if (byteArray[i] == 0 && byteArray[i + 1] == 0) {
				return (i + 2);
			}
			i += 2;
		}
		return -1;
	}

	private ArrayDataType createArrayOfShorts(int len) {
		ArrayDataType array = new ArrayDataType(ShortDataType.dataType, len, 2);
		return array;
	}

	private int addComp(DataType dataType, int len, String fieldName, Address address,
			List<DataTypeComponent> comps, int currentOffset) {
		if (len > 0) {
			ReadOnlyDataTypeComponent readOnlyDataTypeComponent =
				new ReadOnlyDataTypeComponent(dataType, this, len, comps.size(), currentOffset,
					fieldName, null);
			comps.add(readOnlyDataTypeComponent);
			currentOffset += len;
		}
		return currentOffset;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getRepresentation(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int len) {
		return "<Dialog-Resource>";
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "Dialog";
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new DialogResourceDataType(dtm);
	}

}
