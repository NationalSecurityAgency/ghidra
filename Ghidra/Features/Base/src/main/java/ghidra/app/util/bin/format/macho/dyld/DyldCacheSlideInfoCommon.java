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
 * Class for representing the common components of the various dyld_cache_slide_info structures.
 * The intent is for the the full dyld_cache_slide_info structures to extend this and add their
 * specific parts.
 * 
 * @see <a href="https://opensource.apple.com/source/dyld/dyld-625.13/launch-cache/dyld_cache_format.h.auto.html">launch-cache/dyld_cache_format.h</a> 
 */
public class DyldCacheSlideInfoCommon implements StructConverter {

	protected int version;

	/**
	 * Create a new {@link DyldCacheSlideInfoCommon}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD slide info
	 * @throws IOException if there was an IO-related problem creating the DYLD slide info
	 */
	public DyldCacheSlideInfoCommon(BinaryReader reader) throws IOException {
		version = reader.readNextInt();
	}

	/**
	 * Gets the version of the DYLD slide info.
	 * 
	 * @return The version of the DYLD slide info.
	 */
	public int getVersion() {
		return version;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_cache_slide_info", 0);
		struct.add(DWORD, "version", "");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
