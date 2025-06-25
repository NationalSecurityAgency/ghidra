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
package ghidra.file.formats.android.oat.quickmethod;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/android10-release/runtime/oat_quick_method_header.h#158">android10-release/runtime/oat_quick_method_header.h</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/android11-release/runtime/oat_quick_method_header.h#175">android11-release/runtime/oat_quick_method_header.h</a>
 */
public class OatQuickMethodHeader_Q_R extends OatQuickMethodHeader {
	private int vmap_table_offset_;
	private int code_size_;
	private byte[] code_;

	OatQuickMethodHeader_Q_R(BinaryReader reader) throws IOException {
		vmap_table_offset_ = reader.readNextInt();
		code_size_ = reader.readNextInt();
		code_ = reader.readNextByteArray(code_size_);
	}

	/** 
	 * The offset in bytes from the start of the vmap table to the end of the header.
	 * @return the VMAP table offset
	 */
	public int getVmapTableOffset() {
		return vmap_table_offset_;
	}

	/**
	 * The code size in bytes.
	 * @return the code size
	 */
	@Override
	public int getCodeSize() {
		return code_size_;
	}

	/**
	 * The actual code.
	 * @return the actual code bytes
	 */
	public byte[] getCode() {
		return code_;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(OatQuickMethodHeader_Q_R.class.getSimpleName(), 0);
		structure.add(DWORD, "vmap_table_offset_", null);
		structure.add(DWORD, "code_size_", null);
		structure.setCategoryPath(new CategoryPath("/oat"));
		return structure;
	}
}
