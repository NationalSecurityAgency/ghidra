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
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a dyld_cache_range_entry structure.
 * 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h">dyld_cache_format.h</a> 
 */
@SuppressWarnings("unused")
public class DyldCacheRangeEntry implements StructConverter {

	private long startAddress;
	private int size;
	private int imageIndex;

	/**
	 * Create a new {@link DyldCacheRangeEntry}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD range entry
	 * @throws IOException if there was an IO-related problem creating the DYLD range entry
	 */
	public DyldCacheRangeEntry(BinaryReader reader) throws IOException {
		startAddress = reader.readNextLong();
		size = reader.readNextInt();
		imageIndex = reader.readNextInt();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_cache_range_entry", 0);
		struct.add(QWORD, "startAddress", "");
		struct.add(DWORD, "size", "");
		struct.add(DWORD, "imageIndex", "");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
