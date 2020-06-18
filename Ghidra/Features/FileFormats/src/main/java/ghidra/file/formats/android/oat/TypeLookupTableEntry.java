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
package ghidra.file.formats.android.oat;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/art/+/oreo-release/runtime/type_lookup_table.h#100
 * https://android.googlesource.com/platform/art/+/oreo-m2-release/runtime/type_lookup_table.h#100
 * https://android.googlesource.com/platform/art/+/pie-release/runtime/type_lookup_table.h#102
 * 
 * 
 */
public class TypeLookupTableEntry implements StructConverter {

	private int str_offset;
	private short data;
	private short next_pos_delta;

	public TypeLookupTableEntry(BinaryReader reader) throws IOException {
		str_offset = reader.readNextInt();
		data = reader.readNextShort();
		next_pos_delta = reader.readNextShort();
	}

	public int getStringOffset() {
		return str_offset;
	}

	public short getData() {
		return data;
	}

	public short getNextPosDelta() {
		return next_pos_delta;
	}

	public boolean isEmpty() {
		return str_offset == 0;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(TypeLookupTableEntry.class);
	}

}
