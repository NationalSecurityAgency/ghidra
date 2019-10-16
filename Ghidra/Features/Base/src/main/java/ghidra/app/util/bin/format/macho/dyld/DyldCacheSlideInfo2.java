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
package ghidra.app.util.bin.format.macho.dyld;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a dyld_cache_slide_info2 structure.
 * 
 * @see <a href="https://opensource.apple.com/source/dyld/dyld-625.13/launch-cache/dyld_cache_format.h.auto.html">launch-cache/dyld_cache_format.h</a> 
 */
public class DyldCacheSlideInfo2 extends DyldCacheSlideInfoCommon {

	private int page_size;
	private int page_starts_offset;
	private int page_starts_count;
	private int page_extras_offset;
	private int page_extras_count;
	private long delta_mask;
	private long value_add;
	private short page_starts_entries[];
	private short page_extras_entries[];

	public long getPageSize() {
		return ((long)page_size) & 0xffffffff;
	}

	public long getPageStartsOffset() {
		return ((long) page_starts_offset) & 0xffffffff;
	}

	public long getPageStartsCount() {
		return ((long) page_starts_count) & 0xffffffff;
	}

	public long getPageExtrasOffset() {
		return ((long) page_extras_offset) & 0xffffffff;
	}

	public long getPageExtrasCount() {
		return ((long) page_extras_count) & 0xffffffff;
	}

	public long getDeltaMask() {
		return delta_mask;
	}

	public long getValueAdd() {
		return value_add;
	}
	
	public short[] getPageStartsEntries() {
		return page_starts_entries;
	}
	
	public short[] getPageExtrasEntries() {
		return page_extras_entries;
	}
	
	/**
	 * Create a new {@link DyldCacheSlideInfo2}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD slide info 2
	 * @throws IOException if there was an IO-related problem creating the DYLD slide info 2
	 */
	public DyldCacheSlideInfo2(BinaryReader reader) throws IOException {
		super(reader);
		page_size = reader.readNextInt();
		page_starts_offset = reader.readNextInt();
		page_starts_count = reader.readNextInt();
		page_extras_offset = reader.readNextInt();
		page_extras_count = reader.readNextInt();
		delta_mask = reader.readNextLong();
		value_add = reader.readNextLong();
		page_starts_entries = reader.readNextShortArray(page_starts_count);
		page_extras_entries = reader.readNextShortArray(page_extras_count);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_cache_slide_info2", 0);
		struct.add(DWORD, "version", "");
		struct.add(DWORD, "page_size", "");
		struct.add(DWORD, "page_starts_offset", "");
		struct.add(DWORD, "page_starts_count", "");
		struct.add(DWORD, "page_extras_offset", "");
		struct.add(DWORD, "page_extras_count", "");
		struct.add(QWORD, "delta_mask", "");
		struct.add(QWORD, "value_add", "");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
