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
 * See https://android.googlesource.com/platform/art/+/oreo-m2-release/runtime/method_bss_mapping.h
 * <br>
 * MethodBssMappingEntry describes a mapping of up to 17 method indexes to their offsets
 * in the .bss. The highest index and its associated .bss offset are stored in plain form
 * as `method_index` and `bss_offset`, respectively, while the additional indexes can be
 * stored in compressed form if their associated .bss entries are consecutive and in the
 * method index order. Each of the 16 bits of the `index_mask` corresponds to one of the
 * previous 16 method indexes and indicates whether there is a .bss entry for that index.
 */
public class MethodBssMappingEntry implements StructConverter {

	private short method_index;
	private short index_mask;
	private int bss_offset;

	MethodBssMappingEntry(BinaryReader reader) throws IOException {
		method_index = reader.readNextShort();
		index_mask = reader.readNextShort();
		bss_offset = reader.readNextInt();
	}

	public short getMethodIndex() {
		return method_index;
	}

	public short getIndexMask() {
		return index_mask;
	}

	public int getBssOffset() {
		return bss_offset;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(MethodBssMappingEntry.class);
	}
}
