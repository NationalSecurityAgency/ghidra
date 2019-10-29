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
 * Represents a dyld_cache_image_text_info structure.
 * 
 * @see <a href="https://opensource.apple.com/source/dyld/dyld-625.13/launch-cache/dyld_cache_format.h.auto.html">launch-cache/dyld_cache_format.h</a> 
 */
@SuppressWarnings("unused")
public class DyldCacheImageTextInfo implements StructConverter {

	private byte[] uuid;
	private long loadAddress;
	private int textSegmentSize;
	private int pathOffset;

	private String path;

	/**
	 * Create a new {@link DyldCacheImageTextInfo}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD image text info
	 * @throws IOException if there was an IO-related problem creating the DYLD image text info
	 */
	public DyldCacheImageTextInfo(BinaryReader reader) throws IOException {
		uuid = reader.readNextByteArray(16);
		loadAddress = reader.readNextLong();
		textSegmentSize = reader.readNextInt();
		pathOffset = reader.readNextInt();

		path = reader.readAsciiString(pathOffset);
	}

	/**
	 * Gets the path of the image text.
	 * 
	 * @return The path of the image text.
	 */
	public String getPath() {
		return path;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_cache_image_text_info", 0);
		struct.add(new ArrayDataType(BYTE, 16, 1), "uuid", "");
		struct.add(QWORD, "loadAddress", "");
		struct.add(DWORD, "textSegmentSize", "");
		struct.add(DWORD, "pathOffset", "");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}

