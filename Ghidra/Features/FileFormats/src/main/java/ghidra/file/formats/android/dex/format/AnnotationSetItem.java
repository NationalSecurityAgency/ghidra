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
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/art/+/master/libdexfile/dex/dex_file_structs.h#258
 */
public class AnnotationSetItem implements StructConverter {

	private static final int MAX_SANE_COUNT = 0x1000;

	private int size_;

	private int[] entries_;

	public AnnotationSetItem(BinaryReader reader, DexHeader dexHeader) throws IOException {
		size_ = reader.readNextInt();
		if (size_ > MAX_SANE_COUNT) {
			throw new IOException(
				"Too many annotations specified: 0x" + Integer.toHexString(size_));
		}
		entries_ = reader.readNextIntArray(size_);

	}

	public int getSize() {
		return size_;
	}

	public int[] getEntries() {
		return entries_;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("annotation_set_item_" + size_, 0);
		structure.add(DWORD, "size_", null);
		if (size_ > 0) {
			ArrayDataType array = new ArrayDataType(DWORD, size_, DWORD.getLength());
			structure.add(array, "entries_", null);
		}
		structure.setCategoryPath(new CategoryPath("/dex/annotation_set_item"));
		return structure;
	}

}
