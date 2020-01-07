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
 * Represents a dyld_cache_slide_info structure.
 * 
 * @see <a href="https://opensource.apple.com/source/dyld/dyld-625.13/launch-cache/dyld_cache_format.h.auto.html">launch-cache/dyld_cache_format.h</a> 
 */
public class DyldCacheSlideInfo1 extends DyldCacheSlideInfoCommon {

	private int toc_offset;
	private int toc_count;
	private int entries_offset;
	private int entries_count;
	private int entries_size;

	public int getTocOffset() {
		return toc_offset;
	}

	public int getTocCount() {
		return toc_count;
	}

	public int getEntriesOffset() {
		return entries_offset;
	}

	public int getEntriesCount() {
		return entries_count;
	}

	public int getEntriesSize() {
		return entries_size;
	}

	/**
	 * Create a new {@link DyldCacheSlideInfo1}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD slide info 1
	 * @throws IOException if there was an IO-related problem creating the DYLD slide info 1
	 */
	public DyldCacheSlideInfo1(BinaryReader reader) throws IOException {
		super(reader);
		toc_offset = reader.readNextInt();
		toc_count = reader.readNextInt();
		entries_offset = reader.readNextInt();
		entries_count = reader.readNextInt();
		entries_size = reader.readNextInt();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_cache_slide_info", 0);
		struct.add(DWORD, "version", "");
		struct.add(DWORD, "toc_offset", "");
		struct.add(DWORD, "toc_count", "");
		struct.add(DWORD, "entries_offset", "");
		struct.add(DWORD, "entries_count", "");
		struct.add(DWORD, "entries_size", "");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
