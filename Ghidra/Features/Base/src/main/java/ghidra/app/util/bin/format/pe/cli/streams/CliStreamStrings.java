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
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.cli.CliStreamHeader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * The Strings stream contains null-terminated UTF8 strings.
 * When the stream is present, the first entry is always the empty string.
 * This stream may contain garbage in its unreachable parts.
 */
public class CliStreamStrings extends CliAbstractStream {

	private List<Integer> stringIndexes;
	private List<Integer> stringSizes;

	/**
	 * Gets the name of this stream.
	 * 
	 * @return The name of this stream.
	 */
	public static String getName() {
		return "#Strings";
	}

	/**
	 * Creates a new Strings stream.
	 * 
	 * @param header The stream header associated with this stream.
	 * @param offset The reader offset where this stream starts. 
	 * @param rva The relative virtual address where this stream starts.
	 * @param reader A reader that is used to read the stream.
	 * @throws IOException if there is a problem reading the stream.
	 */
	public CliStreamStrings(CliStreamHeader header, long offset, int rva, BinaryReader reader)
			throws IOException {
		super(header, offset, rva, reader);
		stringIndexes = new ArrayList<>();
		stringSizes = new ArrayList<>();
	}

	@Override
	public boolean parse() throws IOException {
		reader.setPointerIndex(offset);

		int bytesRead = 0;
		int stringLength = 0;
		int prevOffset = 0;

		// Loop through the data looking for NULL terminators
		while (bytesRead < header.getSize()) {
			int currentByte = reader.readNextUnsignedByte();
			stringLength++;
			bytesRead++;

			if (currentByte == 0) {
				stringIndexes.add(prevOffset);
				prevOffset = bytesRead;

				// Record the length of the UTF-8 string including the NULL terminator
				stringSizes.add(stringLength);

				// We're moving on to the next string so reset to 0
				stringLength = 0;
			}
		}

		return true;
	}

	/**
	 * Gets the string at the given index.
	 * 
	 * @param index The index of the string to get.
	 * @return The string at the given index.  Could be null if the index was invalid or there was
	 *   a problem reading the string.
	 */
	public String getString(int index) {

		if (stringIndexes.size() == 0 || stringSizes.size() == 0) {
			return null;
		}

		int lastIndex = stringIndexes.get(stringIndexes.size() - 1);
		int lastSize = stringSizes.get(stringSizes.size() - 1);

		if (index < 0 || index >= lastIndex + lastSize) {
			return null;
		}

		int stringLength = 0;
		int stringLengthIndex = Collections.binarySearch(stringIndexes, index);
		if (stringLengthIndex >= 0) {
			stringLength = stringSizes.get(stringLengthIndex);
		}
		else {
			// Reinterpret to the closest offset of a complete string prior
			// to the offset, then get the remainder string length
			stringLengthIndex = (-stringLengthIndex - 1) - 1;
			stringLength =
				stringSizes.get(stringLengthIndex) - (index - stringIndexes.get(stringLengthIndex));
		}

		try {
			// Grab an array of bytes at the index and convert to UTF-8, and don't
			// include the NULL terminator
			return new String(reader.readByteArray(offset + index, stringLength - 1),
				StandardCharsets.UTF_8);
		}
		catch (IOException e) {
			return null;
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(new CategoryPath(PATH), header.getName(), 0);

		for (int i = 0; i < stringSizes.size(); i++) {
			struct.add(UTF8, stringSizes.get(i),
				"[" + Integer.toHexString(stringIndexes.get(i)) + "]", null);
		}
		return struct;
	}
}
