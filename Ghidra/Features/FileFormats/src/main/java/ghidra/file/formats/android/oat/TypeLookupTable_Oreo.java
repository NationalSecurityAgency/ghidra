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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/art/+/oreo-release/runtime/type_lookup_table.h#161
 * https://android.googlesource.com/platform/art/+/oreo-m2-release/runtime/type_lookup_table.h#161
 */
public class TypeLookupTable_Oreo extends TypeLookupTable {

	private int dex_file_begin_;
	private int raw_data_length_;
	private int mask_;
	private List<TypeLookupTableEntry> entries_ = new ArrayList<TypeLookupTableEntry>();
	// owns_entries_ specifies if the lookup table owns the entries_ array.
	private int owns_entries_;

	public TypeLookupTable_Oreo(BinaryReader reader) throws IOException {
		// TODO Auto-generated constructor stub
	}

	public int getDexFileBegin() {
		return dex_file_begin_;
	}

	public int getRawDataLength() {
		return raw_data_length_;
	}

	public int getMask() {
		return mask_;
	}

	public List<TypeLookupTableEntry> getEntries() {
		return entries_;
	}

	/**
	 * owns_entries_ specifies if the lookup table owns the entries_ array.
	 */
	public boolean isOwnsEntries() {
		return owns_entries_ == 0;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String className = StructConverterUtil.parseName(TypeLookupTable_Oreo.class);
		Structure struct = new StructureDataType(className, 0);
		struct.add(DWORD, "dex_file_begin_", null);
		struct.add(DWORD, "raw_data_length_", null);
		struct.add(DWORD, "mask_", null);
		for (int i = 0; i < entries_.size(); ++i) {
			struct.add(entries_.get(i).toDataType(), "entry_" + i, null);
		}
		struct.add(DWORD, "owns_entries_", null);
		return struct;
	}

}
