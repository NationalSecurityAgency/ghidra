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
package ghidra.file.formats.ext4;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class Ext4ExtentHeader implements StructConverter {
	private static final int SIZEOF = 12;
	
	private short eh_magic;
	private short eh_entries;
	private short eh_max;
	private short eh_depth;
	private int eh_generation;
	
	/**
	 * Read a Ext4ExtentHeader from the stream.
	 * 
	 * @param reader BinaryReader to read from
	 * @return new Ext4ExtentHeader instance, or null if eof or no magic value
	 * @throws IOException if error
	 */
	public static Ext4ExtentHeader read(BinaryReader reader) throws IOException {
		if (reader.getPointerIndex() + SIZEOF >= reader.length() ||
			Short.toUnsignedInt(reader.peekNextShort()) != Ext4Constants.EXTENT_HEADER_MAGIC) {
			return null;
		}
		return new Ext4ExtentHeader(reader);
	}

	public Ext4ExtentHeader( ByteProvider provider ) throws IOException {
		this( new BinaryReader( provider, true ) );
	}
	
	public Ext4ExtentHeader( BinaryReader reader ) throws IOException {
		eh_magic = reader.readNextShort();
		eh_entries = reader.readNextShort();
		eh_max = reader.readNextShort();
		eh_depth = reader.readNextShort();
		eh_generation = reader.readNextInt();
	}

	public short getEh_magic() {
		return eh_magic;
	}

	public short getEh_entries() {
		return eh_entries;
	}

	public short getEh_max() {
		return eh_max;
	}

	public short getEh_depth() {
		return eh_depth;
	}

	public int getEh_generation() {
		return eh_generation;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("ext4_extent_header", 0);
		structure.add(WORD, "eh_magic", null);
		structure.add(WORD, "eh_entries", null);
		structure.add(WORD, "eh_max", null);
		structure.add(WORD, "eh_depth", null);
		structure.add(DWORD, "eh_generation", null);
		return structure;
	}

}
