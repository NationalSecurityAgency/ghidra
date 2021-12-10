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
package ghidra.file.formats.android.cdex;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.program.model.data.*;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;

/**
 * CDEX Header extends DEX header, but adds additional members
 * 
 * class Header : public DexFile::Header {
 * 
 * 
 * https://android.googlesource.com/platform/art/+/master/libdexfile/dex/compact_dex_file.h
 */
public class CDexHeader extends DexHeader {

	private int feature_flags_;
	private int debug_info_offsets_pos_;
	private int debug_info_offsets_table_offset_;
	private int debug_info_base_;
	private int owned_data_begin_;
	private int owned_data_end_;

	public CDexHeader(BinaryReader reader) throws IOException {
		super(reader);

		feature_flags_ = reader.readNextInt();
		debug_info_offsets_pos_ = reader.readNextInt();
		debug_info_offsets_table_offset_ = reader.readNextInt();
		debug_info_base_ = reader.readNextInt();
		owned_data_begin_ = reader.readNextInt();
		owned_data_end_ = reader.readNextInt();
	}

	public int getFeatureFlags() {
		return feature_flags_;
	}

	/**
	 * Position in the compact dex file for the debug info table data starts.
	 * @return position in the compact dex file for the debug info table data starts
	 */
	public int getDebugInfoOffsetsPos() {
		return debug_info_offsets_pos_;
	}

	/**
	 * Offset into the debug info table data where the lookup table exists.
	 * @return offset into the debug info table data where the lookup table is.
	 */
	public int getDebugInfoOffsetsTableOffset() {
		return debug_info_offsets_table_offset_;
	}

	/**
	 * Base offset of where debug info starts in the dex file.
	 * @return base offset of where debug info starts in the dex file
	 */
	public int getDebugInfoBase() {
		return debug_info_base_;
	}

	/**
	 * Range of the shared data section owned by the dex file.
	 * @return range of the shared data section owned by the dex file
	 */
	public int getOwnedDataBegin() {
		return owned_data_begin_;
	}

	/**
	 * Range of the shared data section owned by the dex file.
	 * @return range of the shared data section owned by the dex file.
	 */
	public int getOwnedDataEnd() {
		return owned_data_end_;
	}

	@Override
	public boolean isDataOffsetRelative() {
		return true;
	}

	@Override
	protected void checkMagic() throws IOException {
		if (!CDexConstants.MAGIC.equals(new String(getMagic()))) {
			throw new IOException("not a cdex file.");
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = (Structure) super.toDataType();
		try {
			structure.setName("cdex_header");
		}
		catch (InvalidNameException e) {
			//ignore, can't happen
		}
		structure.setCategoryPath(new CategoryPath("/cdex"));

		structure.add(DWORD, "feature_flags_", null);
		structure.add(DWORD, "debug_info_offsets_pos_", null);
		structure.add(DWORD, "debug_info_offsets_table_offset_", null);
		structure.add(DWORD, "debug_info_base_", null);
		structure.add(DWORD, "owned_data_begin_", null);
		structure.add(DWORD, "owned_data_end_", null);

		// remove comments to prevent data type conflicts
		for (DataTypeComponent component : structure.getComponents()) {
			component.setComment(null);
		}

		return structure;
	}

}
