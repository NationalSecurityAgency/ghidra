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
package ghidra.file.formats.android.dex.format;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class StringDataItem implements StructConverter {
	private static final int MAX_STRING_LEN = 0x200000; // 2Mb'ish

	private int stringLength;
	private int lebLength;
	private int actualLength;
	private String string;

	public StringDataItem(StringIDItem stringItem, BinaryReader reader) throws IOException {
		reader = reader.clone(stringItem.getStringDataOffset());
		LEB128 leb128 = LEB128.readUnsignedValue(reader);
		stringLength = leb128.asUInt32();
		lebLength = leb128.getLength();
		long nullTermIndex =
			getIndexOfByteValue(reader, reader.getPointerIndex(), MAX_STRING_LEN, (byte) 0);
		actualLength = (int) (nullTermIndex - reader.getPointerIndex() + 1);
		byte[] stringBytes = reader.readNextByteArray(actualLength);

		ByteArrayInputStream in = new ByteArrayInputStream(stringBytes);

		char[] out = new char[stringLength];

		string = ModifiedUTF8.decode(in, out);
	}

	public String getString() {
		return string;
	}

	@Override
	public DataType toDataType( ) throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType( "string_data_item_" + actualLength, 0 );
		structure.add( new ArrayDataType( BYTE, lebLength, BYTE.getLength( ) ), "utf16_size", null );
		structure.add( UTF8, actualLength, "data", null );
		structure.setCategoryPath( new CategoryPath( "/dex/string_data_item" ) );
		return structure;
	}

	private static long getIndexOfByteValue(BinaryReader reader, long startIndex, int maxLen,
			byte byteValueToFind) throws IOException {
		long maxIndex = startIndex + maxLen;
		long currentIndex = startIndex;
		while (currentIndex < maxIndex) {
			byte b = reader.readByte(currentIndex);
			if (b == byteValueToFind) {
				return currentIndex;
			}
			currentIndex++;
		}
		return currentIndex;
	}

}
