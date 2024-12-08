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
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.program.model.data.*;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a dyld_subcache_entry structure.
 * 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/cache-builder/dyld_cache_format.h">dyld_cache_format.h</a> 
 */
public class DyldSubcacheEntry implements StructConverter {

	private byte[] uuid;
	private long cacheVMOffset;
	private byte[] cacheExtension;

	/**
	 * Create a new {@link DyldSubcacheEntry}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD subCache entry
	 * @throws IOException if there was an IO-related problem creating the DYLD subCache entry
	 */
	public DyldSubcacheEntry(BinaryReader reader) throws IOException {
		uuid = reader.readNextByteArray(16);
		cacheVMOffset = reader.readNextLong();

		// A bit of a hack.  Is there a safer way to know if you are reading a dyld_subcache_entry
		// or a dyld_subcache_entry_v1?
		if (reader.readByte(reader.getPointerIndex()) == '.') {
			cacheExtension = reader.readNextByteArray(32);
		}
	}

	/**
	 * Gets the UUID of the subCache file
	 * 
	 * @return The UUID of the subCache file
	 */
	public String getUuid() {
		return NumericUtilities.convertBytesToString(uuid);
	}

	/**
	 * Gets the offset of this subCache from the main cache base address
	 * 
	 * @return The offset of this subCache from the main cache base address
	 */
	public long getCacheVMOffset() {
		return cacheVMOffset;
	}

	/**
	 * Gets the extension of this subCache, if it is known
	 * 
	 * @return The extension of this subCache, or null if it is not known
	 */
	public String getCacheExtension() {
		if (cacheExtension == null) {
			return null;
		}
		int i;
		for (i = 0; i < cacheExtension.length; i++) {
			if (cacheExtension[i] == 0) {
				break;
			}
		}
		return new String(cacheExtension, 0, i, StandardCharsets.US_ASCII);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_subcache_entry", 0);
		struct.add(new ArrayDataType(BYTE, 16, 1), "uuid", "The UUID of the subCache file");
		struct.add(QWORD, "cacheVMOffset",
			"The offset of this subcache from the main cache base address");
		if (cacheExtension != null) {
			struct.add(new ArrayDataType(ASCII, 32, 1), "cacheExtension",
				"The extension of the subCache file");
		}
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
