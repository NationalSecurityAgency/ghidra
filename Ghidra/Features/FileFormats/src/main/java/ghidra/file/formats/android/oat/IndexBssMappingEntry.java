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
 * See https://android.googlesource.com/platform/art/+/master/runtime/index_bss_mapping.h
 *
 */
public class IndexBssMappingEntry implements StructConverter {

	private int index_and_mask;
	private int bss_offset;

	IndexBssMappingEntry(BinaryReader reader) throws IOException {
		index_and_mask = reader.readNextInt();
		bss_offset = reader.readNextInt();
	}

	public int getIndexAndMask() {
		return index_and_mask;
	}

	public int getIndex(int index_bits) {
		return index_and_mask & IndexBssUtilities.indexMask(index_bits);
	}

	public int getMask(int index_bits) {
		return index_and_mask >> index_bits;
	}

	public int getBssOffset() {
		return bss_offset;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(IndexBssMappingEntry.class);
	}
}
