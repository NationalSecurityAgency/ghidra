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
package ghidra.app.util.bin.format.pe.cli.streams;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.cli.CliStreamHeader;
import ghidra.app.util.bin.format.pe.cli.blobs.CliBlob;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * The User Strings stream contains blobs of 16-bit Unicode strings.
 * When the stream is present, the first entry is always the byte 0x00.
 * This stream may contain garbage in its unreachable parts.
 */
public class CliStreamUserStrings extends CliStreamBlob {

	/**
	 * Gets the name of this stream.
	 * 
	 * @return The name of this stream.
	 */
	public static String getName() {
		return "#US";
	}

	/**
	 * Creates a new {@link CliStreamUserStrings}.
	 * 
	 * @param header The stream header associated with this stream.
	 * @param fileOffset The file offset where this stream starts. 
	 * @param rva The relative virtual address where this stream starts.
	 * @param reader A reader that is set to the start of the stream.
	 * @throws IOException if there is a problem reading the stream.
	 */
	public CliStreamUserStrings(CliStreamHeader header, long fileOffset, int rva,
			BinaryReader reader) throws IOException {
		super(header, fileOffset, rva, reader);
	}

	/**
	 * Gets the user string at the given index.
	 * 
	 * @param index The index of the user string to get.
	 * @return The user string at the given index.  Could be null if the index was invalid or
	 *   there was a problem reading the user string.
	 */
	public String getUserString(int index) {
		byte[] bytes = blobMap.get(index).getContents();
		// Must explicitly specify UTF_16LE or the string gets mangled
		return new String(bytes, 0, bytes.length - 1, StandardCharsets.UTF_16LE);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(new CategoryPath(PATH), header.getName(), 0);
		struct.add(BYTE, "Reserved", "Always 0");
		for (Map.Entry<Integer, CliBlob> entry : blobMap.entrySet()) {
			int index = entry.getKey();
			CliBlob blob = entry.getValue();
			struct.add(blob.getSizeDataType(), "Next string size", null);
			if (blob.getContentsSize() > 0) {
				if (blob.getContentsSize() - 1 > 0) {
					struct.add(UTF16, blob.getContentsSize() - 1,
						"[" + Integer.toHexString(index) + "]", null);
				}
				struct.add(BYTE, "Extra byte", "0x01 if string contains non-ASCII");
			}
		}
		return struct;
	}
}
