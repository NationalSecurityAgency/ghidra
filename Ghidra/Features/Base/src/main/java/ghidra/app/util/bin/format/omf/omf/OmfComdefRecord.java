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
package ghidra.app.util.bin.format.omf.omf;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.omf.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class OmfComdefRecord extends OmfExternalSymbol {

	private record Reference(OmfString name, OmfIndex typeIndex, OmfCommunalLength communalLength1,
			OmfCommunalLength communalLength2) {}
	private List<Reference> refs = new ArrayList<>();

	public OmfComdefRecord(BinaryReader reader, boolean isStatic) throws IOException {
		super(reader, isStatic);
	}

	@Override
	public void parseData() throws IOException, OmfException {
		while (dataReader.getPointerIndex() < dataEnd) {
			OmfString name = OmfUtils.readString(dataReader);
			OmfIndex typeIndex = OmfUtils.readIndex(dataReader);
			byte dataType = dataReader.readNextByte();
			int byteLength = 0;
			if (dataType == 0x61) {		// FAR data, reads numElements and elSize
				OmfCommunalLength numElements = new OmfCommunalLength(dataReader);
				OmfCommunalLength elSize = new OmfCommunalLength(dataReader);
				byteLength = numElements.value * elSize.value;
				refs.add(new Reference(name, typeIndex, numElements, elSize));
			}
			else {
				// Values 1 thru 5f plus 61, read the byte length
				OmfCommunalLength communalLength = new OmfCommunalLength(dataReader);
				byteLength = communalLength.value;
				refs.add(new Reference(name, typeIndex, communalLength, null));
			}
			symbols.add(new OmfSymbol(name.str(), typeIndex.value(), 0, dataType, byteLength));
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(OmfRecordTypes.getName(recordType), 0);
		struct.add(BYTE, "type", null);
		struct.add(WORD, "length", null);
		for (Reference ref : refs) {
			struct.add(ref.name.toDataType(), ref.name.getDataTypeSize(), "name", null);
			struct.add(ref.typeIndex.toDataType(), "type_index", null);
			struct.add(BYTE, "data_type", null);
			struct.add(ref.communalLength1.toDataType(), "communal_length", null);
			if (ref.communalLength2 != null) {
				struct.add(ref.communalLength2.toDataType(), "communal_length", null);
			}
		}
		struct.add(BYTE, "checksum", null);

		struct.setCategoryPath(new CategoryPath(OmfUtils.CATEGORY_PATH));
		return struct;
	}

	/**
	 * A OMF COMDEF "communal length"
	 */
	private static class OmfCommunalLength implements StructConverter {

		private int numBytes;
		private int value;

		public OmfCommunalLength(BinaryReader reader) throws OmfException, IOException {
			long origIndex = reader.getPointerIndex();
			int b = reader.readNextUnsignedByte();
			if (b <= 128) {
				value = b;
			}
			else if (b == 0x81) {
				value = reader.readNextUnsignedShort();
			}
			else if (b == 0x84) {
				value = reader.readNextUnsignedShort();
				int hithird = reader.readNextUnsignedByte();
				value += (hithird << 16);
			}
			else if (b == 0x88) {
				value = reader.readNextInt();
			}
			else {
				throw new OmfException("Illegal communal length encoding");
			}
			numBytes = (int)(reader.getPointerIndex() - origIndex);
		}

		@Override
		public DataType toDataType() throws DuplicateNameException, IOException {
			StructureDataType struct =
				new StructureDataType(OmfCommunalLength.class.getSimpleName(), 0);
			switch (numBytes) {
				case 1:
					struct.add(BYTE, "value", null);
					break;
				case 3:
					struct.add(BYTE, "type", null);
					struct.add(WORD, "value", null);
					break;
				case 4:
					struct.add(BYTE, "type", null);
					struct.add(Integer3DataType.dataType, "value", null);
					break;
				case 5:
					struct.add(BYTE, "type", null);
					struct.add(DWORD, "value", null);
					break;

			}
			struct.setCategoryPath(new CategoryPath(OmfUtils.CATEGORY_PATH));
			return struct;
		}
	}
}
