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
 * Represents a dyld_cache_accelerator_initializer structure.
 * 
 * @see <a href="https://opensource.apple.com/source/dyld/dyld-625.13/launch-cache/dyld_cache_format.h.auto.html">launch-cache/dyld_cache_format.h</a> 
 */
@SuppressWarnings("unused")
public class DyldCacheAcceleratorInitializer implements StructConverter {

	private int functionsOffset;
	private int imageIndex;

	/**
	 * Create a new {@link DyldCacheAcceleratorInitializer}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD accelerator 
	 *   initializer
	 * @throws IOException if there was an IO-related problem creating the DYLD accelerator
	 *   initializer
	 */
	public DyldCacheAcceleratorInitializer(BinaryReader reader) throws IOException {
		functionsOffset = reader.readNextInt();
		imageIndex = reader.readNextInt();
	}

	/**
	 * Gets the functions offset, which is an address offset from the start of the cache mapping.
	 * 
	 * @return The functions offset,  which is an address offset from the start of the cache 
	 *   mapping
	 */
	public int getFunctionsOffset() {
		return functionsOffset;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_cache_accelerator_initializer", 0);
		struct.add(DWORD, "functionsOffset", "");
		struct.add(DWORD, "imageIndex", "");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
