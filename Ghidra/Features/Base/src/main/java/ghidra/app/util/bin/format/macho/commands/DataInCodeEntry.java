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
package ghidra.app.util.bin.format.macho.commands;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a data_in_code_entry structure
 * 
 * @see <a href="https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h">EXTERNAL_HEADERS/mach-o/loader.h</a> 
 */
public class DataInCodeEntry implements StructConverter {

	/**
	 * The size (in bytes) of a {@link DataInCodeEntry} structure
	 */
	public static final int SIZE = 8;

	private long offset;
	private int length;
	private short kind;

	/**
	 * Creates a new {@link DataInCodeEntry}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public DataInCodeEntry(BinaryReader reader) throws IOException {
		offset = reader.readNextUnsignedInt();
		length = reader.readNextUnsignedShort();
		kind = reader.readNextShort();
	}

	/**
	 * Gets the offset
	 * 
	 * @return The offset
	 */
	public long getOffset() {
		return offset;
	}

	/**
	 * Gets the length
	 * 
	 * @return The length
	 */
	public int getLength() {
		return length;
	}

	/**
	 * Gets the kind
	 * 
	 * @return The kind
	 */
	public short getKind() {
		return kind;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("data_in_code_entry", 0);
		struct.add(DWORD, "offset", "from mach_header to start of data range");
		struct.add(WORD, "length", "number of bytes in data range");
		struct.add(WORD, "kind",
			"DICE_KIND_DATA=1, DICE_KIND_JUMP_TABLE8=2, DICE_KIND_JUMP_TABLE16=3, DICE_KIND_JUMP_TABLE32=4, DICE_KIND_ABS_JUMP_TABLE32=5");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
