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

import java.util.ArrayList;
import java.util.List;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.*;
import ghidra.util.classfinder.ClassTranslator;

public class MUIResourceDataType extends DynamicDataType {

	static {
		ClassTranslator.put("ghidra.app.plugin.prototype.data.MUIResourceDataType",
			MUIResourceDataType.class.getName());
	}

	public MUIResourceDataType() {
		this(null, "MUIResource", null);
	}

	public MUIResourceDataType(DataTypeManager dtm) {
		this(null, "MUIResource", dtm);
	}

	protected MUIResourceDataType(CategoryPath path, String name, DataTypeManager dtm) {
		super(path, name, dtm);
	}

	@Override
	public String getDescription() {
		return "MUI (Multilingual User Interface) Resource Data Type";
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "MUIRes";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return "MUI";
	}

	private static byte[] MAGIC = { (byte) 0xcd, (byte) 0xfe, (byte) 0xcd, (byte) 0xfe };

	private static String[] names =
		{ "dwMainName", "dwMainID", "dwMUIName", "dwMUIID", "dwLanguage", "dwFallbackLanguage" };

	@Override
	protected DataTypeComponent[] getAllComponents(MemBuffer mbIn) {
		List<DataTypeComponent> comps = new ArrayList<>();
		int tempOffset = 0;
		MemBuffer memBuffer = mbIn;
		int[] offsets = new int[6];
		int[] sizes = new int[6];

		byte[] bytes = new byte[4];
		if (memBuffer.getBytes(bytes, 0) < 4) {
			Msg.debug(this, "Can't read bytes for MUI File Header at " + mbIn.getAddress());
		}
		if (checkMagic(memBuffer)) {
			StructureDataType sdt = MUIStructureHeader();
			tempOffset = addComp(sdt, sdt.getLength(), "muiResourceHeader",
				memBuffer.getAddress().add(tempOffset), comps, tempOffset);
			sdt = MUIStructureData(tempOffset, memBuffer, offsets, sizes);
			tempOffset = addComp(sdt, sdt.getLength(), "muiResourceData",
				memBuffer.getAddress().add(tempOffset), comps, tempOffset);
		}
		else {
			Msg.debug(this, "Not an MUI resource data type at " + mbIn.getAddress());
		}
		DataTypeComponent[] result = comps.toArray(new DataTypeComponent[comps.size()]);
		return result;
	}

	private StructureDataType MUIStructureHeader() {

		StructureDataType struct = new StructureDataType("FILEMUIINFO", 0);

		struct.add(DWordDataType.dataType, 4, "signature", "");
		struct.add(DWordDataType.dataType, 4, "dwSize", "");
		struct.add(DWordDataType.dataType, 4, "dwVersion", ""); // 0x10000 -> 1.0
		struct.add(DWordDataType.dataType, 4, "padding", "");
		struct.add(DWordDataType.dataType, 4, "dwFileType", "0x11 = normal, 0x12 = .mui");
		struct.add(DWordDataType.dataType, 4, "systemAttributes", "");
		struct.add(DWordDataType.dataType, 4, "ultimateFallbackLocation",
			"0x01 = internal, 0x02 = external");

		ArrayDataType adt16 = new ArrayDataType(ByteDataType.dataType, 16, 1);
		ArrayDataType adt24 = new ArrayDataType(ByteDataType.dataType, 24, 1);

		struct.add(adt16, 16, "serviceChecksum", "");
		struct.add(adt16, 16, "checksum", "");
		struct.add(adt24, 24, "padding60", "");
		struct.add(DWordDataType.dataType, 4, "dwMainNameOffset", "");
		struct.add(DWordDataType.dataType, 4, "dwMainNameSize", "");
		struct.add(DWordDataType.dataType, 4, "dwMainIDOffset", "");
		struct.add(DWordDataType.dataType, 4, "dwMainIDSize", "");
		struct.add(DWordDataType.dataType, 4, "dwMUINameOffset", "");
		struct.add(DWordDataType.dataType, 4, "dwMUINameSize", "");
		struct.add(DWordDataType.dataType, 4, "dwMUIIDOffset", "");
		struct.add(DWordDataType.dataType, 4, "dwMUIIDSize", "");
		struct.add(DWordDataType.dataType, 4, "dwLanguageOffset", "");
		struct.add(DWordDataType.dataType, 4, "dwLanguageSize", "");
		struct.add(DWordDataType.dataType, 4, "dwFallbackLanguageOffset", "");
		struct.add(DWordDataType.dataType, 4, "dwFallbackLanguageSize", "");
		return struct;
	}

	private StructureDataType MUIStructureData(int tempOffset, MemBuffer memBuffer, int[] offsets,
			int[] sizes) {
		StructureDataType struct = new StructureDataType("MUIDATA", 0);
		setArrays(memBuffer, offsets, sizes);
		int paddingOrdinal = 0;
		for (int i = 0; i < 6; i++) {
			int paddingSize = 0;
			while (!(memBuffer.getAddress().add(tempOffset).getOffset() % 8 == 0)) {
				tempOffset++;
				paddingSize++;
			}
			if (paddingSize != 0) {
				struct.add(new ArrayDataType(ByteDataType.dataType, paddingSize, 1),
					"padding_" + (paddingOrdinal++), "");
			}
			if (sizes[i] != 0) {
				if (i == 0 || i == 2 || i == 4 || i == 5) {
					struct.add(UnicodeDataType.dataType, sizes[i], names[i], "");
					tempOffset += sizes[i];
				}
				else {
					ArrayDataType array = new ArrayDataType(ByteDataType.dataType, sizes[i], 1);
					tempOffset += sizes[i];
					struct.add(array, names[i], "");
				}
			}
		}
		return struct;
	}

	private void setArrays(MemBuffer memBuffer, int[] offsets, int[] sizes) {
		byte[] offsetBytes;
		byte[] sizeBytes;
		for (int i = 0; i < 6; i++) {
			offsetBytes = new byte[4];
			sizeBytes = new byte[4];
			try {
				for (int j = 0; j < 4; j++) {
					offsetBytes[j] = memBuffer.getByte(84 + j + 8 * i);
					sizeBytes[j] = memBuffer.getByte(88 + j + 8 * i);
				}
			}
			catch (MemoryAccessException e) {
				Msg.debug(this, "Unexpected exception building MUI resource");
			}
			DataConverter converter = getDataConverter(memBuffer.getMemory().getProgram());
			offsets[i] = converter.getInt(offsetBytes, 0);
			sizes[i] = converter.getInt(sizeBytes, 0);
		}
	}

	private boolean checkMagic(MemBuffer memBuffer) {
		try {
			for (int i = 0; i < MAGIC.length; i++) {
				if (MAGIC[i] != (memBuffer.getByte(i))) {
					return false;
				}
			}
		}
		catch (MemoryAccessException e) {
			Msg.debug(this, "Unexpected exception building MUI resource");
		}
		return true;
	}

	private int addComp(DataType dataType, int length, String fieldName, Address address,
			List<DataTypeComponent> comps, int currentOffset) {
		if (length > 0) {
			ReadOnlyDataTypeComponent readOnlyDataTypeComponent = new ReadOnlyDataTypeComponent(
				dataType, this, length, comps.size(), currentOffset, fieldName, null);
			comps.add(readOnlyDataTypeComponent);
			currentOffset += length;
		}
		return currentOffset;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "<MUI-Resource>";
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "MUI";
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new MUIResourceDataType(dtm);
	}

	private DataConverter getDataConverter(Program program) {
		if (program.getMemory().isBigEndian()) {
			return BigEndianDataConverter.INSTANCE;
		}
		return LittleEndianDataConverter.INSTANCE;
	}

}
