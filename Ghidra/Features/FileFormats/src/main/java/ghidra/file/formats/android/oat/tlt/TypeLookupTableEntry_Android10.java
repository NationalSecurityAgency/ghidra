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
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/art/+/refs/heads/android10-release/libdexfile/dex/type_lookup_table.h#110
 * https://android.googlesource.com/platform/art/+/refs/heads/android11-release/libdexfile/dex/type_lookup_table.h#110
 * https://android.googlesource.com/platform/art/+/refs/heads/android12-release/libdexfile/dex/type_lookup_table.h#110
 */
public class TypeLookupTableEntry_Android10 extends TypeLookupTableEntry {

	public TypeLookupTableEntry_Android10(BinaryReader reader) throws IOException {
		super();
		str_offset_ = reader.readNextInt();
		data_ = reader.readNextInt();
	}

	public boolean isLast(int mask_bits) {
		return getNextPosDelta(mask_bits) == 0;
	}

	public int getNextPosDelta(int mask_bits) {
		return data_ & getMask(mask_bits);
	}

	public int getMask(int mask_bits) {
		//DCHECK_LE(mask_bits, 16u);
		//return ~(std::numeric_limits<uint32_t>::max() << mask_bits);
		return ~(-1 << mask_bits);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(TypeLookupTableEntry_Android10.class.getSimpleName(), 0);
		structure.add(DWORD, "str_offset_", null);
		structure.add(DWORD, "data_", null);
		structure.setCategoryPath(new CategoryPath("/oat"));
		return structure;
	}

}
