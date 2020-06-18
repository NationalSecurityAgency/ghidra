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

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class EncodedField implements StructConverter {

	private long _fileOffset;

	private int fieldIndexDifference;
	private int fieldIndexDifferenceLength;// in bytes

	private int accessFlags;
	private int accessFlagsLength;// in bytes

	public EncodedField(BinaryReader reader) throws IOException {

		LEB128 leb128 = LEB128.readUnsignedValue(reader);
		_fileOffset = leb128.getOffset();
		fieldIndexDifference = leb128.asUInt32();
		fieldIndexDifferenceLength = leb128.getLength();

		leb128 = LEB128.readUnsignedValue(reader);
		accessFlags = leb128.asUInt32();
		accessFlagsLength = leb128.getLength();
	}

	public long getFileOffset() {
		return _fileOffset;
	}

	public int getFieldIndexDifference() {
		return fieldIndexDifference;
	}

	public int getAccessFlags() {
		return accessFlags;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "encoded_field_" + fieldIndexDifferenceLength + "_" + accessFlagsLength;
		Structure structure = new StructureDataType(name, 0);
		structure.add(new ArrayDataType(BYTE, fieldIndexDifferenceLength, BYTE.getLength()),
			"field_idx_diff", null);
		structure.add(new ArrayDataType(BYTE, accessFlagsLength, BYTE.getLength()), "accessFlags",
			null);
		structure.setCategoryPath(new CategoryPath("/dex/encoded_field"));
		return structure;
	}
}
