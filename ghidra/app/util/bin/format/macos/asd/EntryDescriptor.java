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
package ghidra.app.util.bin.format.macos.asd;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

/**
 */
public class EntryDescriptor implements StructConverter {
	private int entryID;
	private int offset;
	private int length;

	private Object _entry;

	EntryDescriptor(BinaryReader reader) throws IOException {
		entryID = reader.readNextInt();
		offset  = reader.readNextInt();
		length  = reader.readNextInt();

		_entry  = EntryFactory.getEntry(reader, this);
	}

	public EntryDescriptor(int entryID, int offset, int length) {
		this.entryID = entryID;
		this.offset  = offset;
		this.length  = length;
	}

	/**
	 * Returns the entry's ID.
	 * Note: 0 is invalid.
	 * @return the entry's ID
	 */
	public int getEntryID() {
		return entryID;
	}
	/**
	 * The offset from the beginning of the file
	 * to the beginning of the entry's data.
	 * @return the offset to entry's data
	 */
	public int getOffset() {
		return offset;
	}
	/**
	 * Returns the length of the entry's data.
	 * The length can be zero (0).
	 * @return the length of the entry's data
	 */
	public int getLength() {
		return length;
	}

	public Object getEntry() {
		return _entry;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(EntryDescriptor.class);
	}

}
