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
import ghidra.app.util.bin.format.macho.commands.SegmentConstants;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a dyld_cache_mapping_and_slide_info structure.
 * 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/cache-builder/dyld_cache_format.h">dyld_cache_format.h</a> 
 */
@SuppressWarnings("unused")
public class DyldCacheMappingAndSlideInfo implements StructConverter {
	
	public static long DYLD_CACHE_MAPPING_AUTH_DATA     = 1 << 3L;
	public static long DYLD_CACHE_MAPPING_DIRTY_DATA    = 1 << 1L;
	public static long DYLD_CACHE_MAPPING_CONST_DATA    = 1 << 2L;

	private long address;
	private long size;
	private long fileOffset;
	private long slideInfoFileOffset;
	private long slideInfoFileSize;
	private long flags;
	private int maxProt;
	private int initProt;

	/**
	 * Create a new {@link DyldCacheImageInfo}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD mapping info
	 * @throws IOException if there was an IO-related problem creating the DYLD mapping info
	 */
	public DyldCacheMappingAndSlideInfo(BinaryReader reader) throws IOException {
		address = reader.readNextLong();
		size = reader.readNextLong();
		fileOffset = reader.readNextLong();
		slideInfoFileOffset = reader.readNextLong();
		slideInfoFileSize = reader.readNextLong();
		flags = reader.readNextLong();
		maxProt = reader.readNextInt();
		initProt = reader.readNextInt();
	}

	/**
	 * Gets the address of the start of the mapping.
	 * 
	 * @return The address of the start of the mapping
	 */
	public long getAddress() {
		return address;
	}

	/**
	 * Gets the size of the mapping.
	 * 
	 * @return The size of the mapping
	 */
	public long getSize() {
		return size;
	}

	/**
	 * Gets the file offset of the start of the mapping.
	 * 
	 * @return The file offset of the start of the mapping
	 */
	public long getFileOffset() {
		return fileOffset;
	}
	
	/**
	 * Get slide info file offset
	 * 
	 * @return slide info file offset
	 */
	public long getSlideInfoFileOffset() {
		return slideInfoFileOffset;
	}

	/**
	 * Get slide info file size
	 * 
	 * @return slide info file size
	 */
	public long getSlideInfoFileSize() {
		return slideInfoFileSize;
	}
	
	/**
	 * Get slide info flags
	 * 
	 * @return slide info flags
	 */	
	public long getFlags() {
		return flags;
	}
	
	public boolean isAuthData() {
		return (flags & DYLD_CACHE_MAPPING_AUTH_DATA) != 0;
	}
	
	public boolean isDirtyData() {
		return (flags & DYLD_CACHE_MAPPING_DIRTY_DATA) != 0;
	}
	
	public boolean isConstData() {
		return (flags & DYLD_CACHE_MAPPING_CONST_DATA) != 0;
	}

	/**
	 * Returns true if the initial protections include READ.
	 * 
	 * @return true if the initial protections include READ
	 */
	public boolean isRead() {
		return (initProt & SegmentConstants.PROTECTION_R) != 0;
	}

	/**
	 * Returns true if the initial protections include WRITE.
	 * 
	 * @return true if the initial protections include WRITE
	 */
	public boolean isWrite() {
		return (initProt & SegmentConstants.PROTECTION_W) != 0;
	}

	/**
	 * Returns true if the initial protections include EXECUTE.
	 * 
	 * @return true if the initial protections include EXECUTE
	 */
	public boolean isExecute() {
		return (initProt & SegmentConstants.PROTECTION_X) != 0;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_cache_mapping_and_slide_info", 0);
		struct.add(QWORD, "address", "");
		struct.add(QWORD, "size", "");
		struct.add(QWORD, "fileOffset", "");
		struct.add(QWORD, "slideInfoFileOffset", "");
		struct.add(QWORD, "slideInfoFileSize", "");
		struct.add(QWORD, "flags", "");
		struct.add(DWORD, "maxProt", "");
		struct.add(DWORD, "initProt", "");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
