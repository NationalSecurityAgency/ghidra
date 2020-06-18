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
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * 
 * https://android.googlesource.com/platform/art/+/refs/heads/kitkat-release/runtime/oat.h#107
 *
 */
public class OatMethodOffsets_KitKat extends OatMethodOffsets {

	private int frame_size_in_bytes_;
	private int core_spill_mask_;
	private int fp_spill_mask_;
	private int mapping_table_offset_;
	private int vmap_table_offset_;
	private int gc_map_offset_;

	public OatMethodOffsets_KitKat(BinaryReader reader) throws IOException {
		super(reader);
		frame_size_in_bytes_ = reader.readNextInt();
		core_spill_mask_ = reader.readNextInt();
		fp_spill_mask_ = reader.readNextInt();
		mapping_table_offset_ = reader.readNextInt();
		vmap_table_offset_ = reader.readNextInt();
		gc_map_offset_ = reader.readNextInt();
	}

	public int getFrameSizeInBytes() {
		return frame_size_in_bytes_;
	}

	public int getCoreSpillMask() {
		return core_spill_mask_;
	}

	public int getFpSpillMask() {
		return fp_spill_mask_;
	}

	public int getMappingTableOffset() {
		return mapping_table_offset_;
	}

	public int getVmapTableOffset() {
		return vmap_table_offset_;
	}

	public int getGcMapOffset() {
		return gc_map_offset_;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = (Structure) super.toDataType();
		structure.add(DWORD, "frame_size_in_bytes_", null);
		structure.add(DWORD, "core_spill_mask_", null);
		structure.add(DWORD, "fp_spill_mask_", null);
		structure.add(DWORD, "mapping_table_offset_", null);
		structure.add(DWORD, "vmap_table_offset_", null);
		structure.add(DWORD, "gc_map_offset_", null);
		structure.add(DWORD, "gc_map_offset_", null);
		structure.setCategoryPath(new CategoryPath("/oat"));
		return structure;
	}
}
