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
package ghidra.file.formats.android.oat.tlt;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/art/+/nougat-release/runtime/type_lookup_table.h#99
 * https://android.googlesource.com/platform/art/+/oreo-release/runtime/type_lookup_table.h#100
 * https://android.googlesource.com/platform/art/+/oreo-m2-release/runtime/type_lookup_table.h#100
 * https://android.googlesource.com/platform/art/+/pie-release/runtime/type_lookup_table.h#102
 * 
 */
public class TypeLookupTableEntry implements StructConverter {

	protected int str_offset_;
	protected int data_;
	protected short next_pos_delta_;

	protected TypeLookupTableEntry() {
		//do nothing
	}

	public TypeLookupTableEntry(BinaryReader reader) throws IOException {
		str_offset_ = reader.readNextInt();
		data_ = Short.toUnsignedInt(reader.readNextShort());
		next_pos_delta_ = reader.readNextShort();
	}

	public int getStringOffset() {
		return str_offset_;
	}

	public int getData() {
		return data_;
	}

	public short getNextPosDelta() {
		return next_pos_delta_;
	}

	public boolean isEmpty() {
		return str_offset_ == 0;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(TypeLookupTableEntry.class.getSimpleName(), 0);
		structure.add(DWORD, "str_offset_", null);
		structure.add(WORD, "data_", null);
		structure.add(WORD, "next_pos_delta_", null);
		structure.setCategoryPath(new CategoryPath("/oat"));
		return structure;
	}

}
