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
 * Represents a dyld_cache_slide_info3 structure.
 * 
 * @see <a href="https://opensource.apple.com/source/dyld/dyld-625.13/launch-cache/dyld_cache_format.h.auto.html">launch-cache/dyld_cache_format.h</a> 
 */
public class DyldCacheSlideInfo3 extends DyldCacheSlideInfoCommon {

	private int page_size;
	private int page_starts_count;
	private long auth_value_add;
	private short page_starts[];

	public int getPageSize() {
		return page_size;
	}

	public int getPageStartsCount() {
		return page_starts_count;
	}

	public long getAuthValueAdd() {
		return auth_value_add;
	}

	public short[] getPageStarts() {
		return page_starts;
	}

	/**
	 * Create a new {@link DyldCacheSlideInfo3}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD slide info 3
	 * @throws IOException if there was an IO-related problem creating the DYLD slide info 3
	 */
	public DyldCacheSlideInfo3(BinaryReader reader) throws IOException {
		super(reader);
		page_size = reader.readNextInt();
		page_starts_count = reader.readNextInt();
		auth_value_add = reader.readNextLong();
		page_starts = reader.readNextShortArray(page_starts_count);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_cache_slide_info3", 0);
		struct.add(DWORD, "version", "");
		struct.add(DWORD, "page_size", "");
		struct.add(DWORD, "page_starts_count", "");
		struct.add(QWORD, "auth_value_add", "");
		struct.add(new ArrayDataType(WORD, page_starts_count, 1), "page_starts", "");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
