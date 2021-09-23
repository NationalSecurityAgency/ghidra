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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/art/+/refs/heads/oreo-release/runtime/oat_quick_method_header.h#190
 * https://android.googlesource.com/platform/art/+/refs/heads/oreo-dr3-release/runtime/oat_quick_method_header.h#191
 * https://android.googlesource.com/platform/art/+/refs/heads/oreo-m2-release/runtime/oat_quick_method_header.h#191
 * https://android.googlesource.com/platform/art/+/refs/heads/pie-release/runtime/oat_quick_method_header.h#191
 */
public class OatQuickMethodHeader_Oreo extends OatQuickMethodHeader {

	final static int SIZE = 16 + QuickMethodFrameInfo.SIZE;

	private int vmap_table_offset_;
	private int method_info_offset_;
	private QuickMethodFrameInfo frame_info_;
	private int code_size_;
	private byte[] code_;

	OatQuickMethodHeader_Oreo(BinaryReader reader) throws IOException {
		vmap_table_offset_ = reader.readNextInt();
		method_info_offset_ = reader.readNextInt();
		frame_info_ = new QuickMethodFrameInfo(reader);
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
	 * The offset in bytes from the start of the method info to the end of the header.
	 * The method info offset is not in the CodeInfo since CodeInfo has good dedupe properties that
	 * would be lost from doing so. The method info memory region contains method indices since they
	 * are hard to dedupe.
	 * @return offset in bytes
	 */
	public int getMethodInfoOffset() {
		return method_info_offset_;
	}

	/**
	 * The stack frame information.
	 * @return the stack frame
	 */
	public QuickMethodFrameInfo getFrameInfo() {
		return frame_info_;
	}

	/**
	 * The code size in bytes. The highest bit is used to signify if the compiled
	 * code with the method header has should_deoptimize flag.
	 */
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
		String className = StructConverterUtil.parseName(OatQuickMethodHeader_Oreo.class);
		Structure structure = new StructureDataType(className, 0);
		structure.add(DWORD, "vmap_table_offset_", null);
		structure.add(DWORD, "method_info_offset_", null);
		structure.add(frame_info_.toDataType(), "frame_info_", null);
		structure.add(DWORD, "code_size_", null);
		structure.setCategoryPath(new CategoryPath("/oat"));
		return structure;
	}
}
