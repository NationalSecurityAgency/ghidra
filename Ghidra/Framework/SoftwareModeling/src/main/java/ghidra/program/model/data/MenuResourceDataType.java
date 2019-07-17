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

import java.util.ArrayList;
import java.util.List;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassTranslator;
import ghidra.util.exception.DuplicateNameException;

public class MenuResourceDataType extends DynamicDataType {

	private static short MF_POPUP = 0x0010;
	private static short MF_END = 0x0080;
	private static short LAST = 0x0090;

	static {
		ClassTranslator.put("ghidra.app.plugin.prototype.data.MenuResourceDataType",
			MenuResourceDataType.class.getName());
	}

	public MenuResourceDataType() {
		this(null, "MenuResource", null);
	}

	public MenuResourceDataType(DataTypeManager dtm) {
		this(null, "MenuResource", dtm);
	}

	protected MenuResourceDataType(CategoryPath path, String name, DataTypeManager dtm) {
		super(path, name, dtm);
	}

	@Override
	public String getDescription() {
		return "Menu stored as a Resource";
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "MenuRes";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return "Menu";
	}

	@Override
	protected DataTypeComponent[] getAllComponents(MemBuffer mbIn) {
		List<DataTypeComponent> comps = new ArrayList<>();
		int tempOffset = 0;
		boolean lastMenuItem = false;
		MemBuffer memBuffer = mbIn;
		short option;

		try {
			//add the header structure
			tempOffset = addMenuItemTemplateHeaderStructure(memBuffer, comps, tempOffset);
			if (tempOffset < 0) {
				return null;
			}

			//loop through menu items and add them
			boolean lastItem = false;
			while (!lastItem) {
				option = memBuffer.getShort(tempOffset);
				tempOffset = addMenuItemTemplate(memBuffer, comps, tempOffset, option);
				//last item in a menu
				if (option == MF_END) {
					if (lastMenuItem == true) {
						lastItem = true;
					}
				}
				//last menu
				if (option == LAST) {
					lastMenuItem = true;
				}
			}
		}
		catch (MemoryAccessException e) {
			Msg.error(this, "buffer error: " + e.getMessage(), e);
		}

		DataTypeComponent[] result = comps.toArray(new DataTypeComponent[comps.size()]);

		return result;
	}

	//adds initial MENUITEM_TEMPLATE_HEADER structure
	private int addMenuItemTemplateHeaderStructure(MemBuffer memBuffer,
			List<DataTypeComponent> comps, int tempOffset) throws MemoryAccessException {

		//check the first two fields to make sure they are both zero - if not, it isn't a valid RT_MENU
		short versionNumber = memBuffer.getShort(tempOffset);
		if (versionNumber != 0x0000) {
			Msg.debug(this, "Invalid MENUITEM_TEMPLATE_HEADER version number");
			return -1;
		}
		short menuItemsOffset = memBuffer.getShort(tempOffset + 2);
		if (menuItemsOffset < 0) {
			Msg.debug(this, "Invalid MENUITEM_TEMPLATE_HEADER offset");
			return -1;
		}

		//once verified as valid, lay down the initial structure
		tempOffset =
			addComp(menuItemTemplateHeaderStructure(), 4, "Menu Item Template Header Structure",
				memBuffer.getAddress(), comps, tempOffset);

		return tempOffset;
	}

	//This is always the first structure in the menu resource
	private StructureDataType menuItemTemplateHeaderStructure() {
		StructureDataType struct = new StructureDataType("MENUITEM_TEMPLATE_HEADER", 0);

		struct.add(WordDataType.dataType);
		struct.add(WordDataType.dataType);

		try {
			struct.getComponent(0).setFieldName("versionNumber");
			struct.getComponent(1).setFieldName("offset");

		}
		catch (DuplicateNameException e) {
			Msg.debug(this, "Unexpected exception building MENUITEM_TEMPLATE_HEADER", e);
		}
		struct.getComponent(0).setComment("Version number of menu");
		struct.getComponent(1).setComment("Menu items offset.");

		return struct;
	}

	//adds a MENUITEM_TEMPLATE structure - one for each menu item
	private int addMenuItemTemplate(MemBuffer memBuffer, List<DataTypeComponent> comps,
			int tempOffset, short mtOption) {

		//If it is a popup there is only an option field, no ID field
		if (mtOption == MF_POPUP) {
			tempOffset =
				addComp(WordDataType.dataType, 2, "mtOption", memBuffer.getAddress(), comps,
					tempOffset);
		}
		//If it is anything else it has option and id fields
		else {
			tempOffset =
				addComp(WordDataType.dataType, 2, "mtOption", memBuffer.getAddress(), comps,
					tempOffset);

			tempOffset =
				addComp(WordDataType.dataType, 2, "mtID", memBuffer.getAddress().add(tempOffset),
					comps, tempOffset);

		}

		tempOffset = addUnicodeString(memBuffer, comps, tempOffset, "Menu Item String");

		return tempOffset;
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

	private int addUnicodeString(MemBuffer memBuffer, List<DataTypeComponent> comps,
			int tempOffset, String title) {

		byte[] tempBytes = new byte[1024];
		memBuffer.getBytes(tempBytes, tempOffset);
		int strLength = findUnicodeLength(tempBytes);
		if (strLength >= 2) {
			tempOffset =
				addComp(UnicodeDataType.dataType, strLength, title,
					memBuffer.getAddress().add(tempOffset), comps, tempOffset);
			return tempOffset;
		}

		return -1;
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

	/**
	 * @see ghidra.program.model.data.DataType#getRepresentation(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "<Menu-Resource>";
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "Menu";
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new MenuResourceDataType(dtm);
	}

}
