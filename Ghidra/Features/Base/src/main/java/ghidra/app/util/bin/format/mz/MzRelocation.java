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
package ghidra.app.util.bin.format.mz;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class MzRelocation implements StructConverter {

	/** The name to use when converting into a structure data type. */
	public static final String NAME = "OLD_IMAGE_DOS_RELOC";

	private int segment;
	private int offset;

	/**
	 * Constructs a new old-style MZ relocation
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the relocation
	 * @throws IOException if there was an IO-related error
	 */
	public MzRelocation(BinaryReader reader) throws IOException {
		offset = Short.toUnsignedInt(reader.readNextShort());
		segment = Short.toUnsignedInt(reader.readNextShort());
	}

	/**
	 * Gets the segment
	 * 
	 * @return The segment
	 */
	public int getSegment() {
		return segment;
	}

	/**
	 * Gets the offset
	 * 
	 * @return The offset
	 */
	public int getOffset() {
		return offset;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.add(WORD, "offset", null);
		struct.add(WORD, "segment", null);
		struct.setCategoryPath(new CategoryPath("/DOS"));
		return struct;
	}

	@Override
	public String toString() {
		return String.format("%04x:%04x", segment, offset);
	}
}
