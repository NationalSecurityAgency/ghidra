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
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/art/+/refs/heads/lollipop-mr1-fi-release/runtime/oat.h#182
 * https://android.googlesource.com/platform/art/+/refs/heads/lollipop-wear-release/runtime/oat.h#184
 * https://android.googlesource.com/platform/art/+/marshmallow-release/runtime/oat.h#185
 */
public class OatQuickMethodHeader_LollipopMR1 extends OatQuickMethodHeader {
	private int mapping_table_offset_;
	private int vmap_table_offset_;
	private int gc_map_offset_;
	private QuickMethodFrameInfo frame_info_;
	private int code_size_;

	OatQuickMethodHeader_LollipopMR1(BinaryReader reader) throws IOException {
		mapping_table_offset_ = reader.readNextInt();
		vmap_table_offset_ = reader.readNextInt();
		gc_map_offset_ = reader.readNextInt();
		frame_info_ = new QuickMethodFrameInfo(reader);
		code_size_ = reader.readNextInt();
	}

	/**
	 * The offset in bytes from the start of the mapping table to the end of the header.
	 * @return offset in bytes
	 */
	public int getMappingTableOffset() {
		return mapping_table_offset_;
	}

	/**
	 * The offset in bytes from the start of the vmap table to the end of the header.
	 * @return VMAP table offset
	 */
	public int getVmapTableOffset() {
		return vmap_table_offset_;
	}

	/**
	 * The offset in bytes from the start of the gc map to the end of the header.
	 * @return GC Map offset
	 */
	public int getGcMapOffset() {
		return gc_map_offset_;
	}

	/**
	 * The stack frame information.
	 * @return the stack frame
	 */
	public QuickMethodFrameInfo getFrameInfo() {
		return frame_info_;
	}

	/**
	 * The code size in bytes.
	 * @return code size in bytes
	 */
	public int getCodeSize() {
		return code_size_;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String className = StructConverterUtil.parseName(OatQuickMethodHeader_LollipopMR1.class);
		Structure structure = new StructureDataType(className, 0);
		structure.add(DWORD, "mapping_table_offset_", null);
		structure.add(DWORD, "vmap_table_offset_", null);
		structure.add(DWORD, "gc_map_offset_", null);
		structure.add(frame_info_.toDataType(), "frame_info_", null);
		structure.add(DWORD, "code_size_", null);
		structure.setCategoryPath(new CategoryPath("/oat"));
		return structure;
	}
}
