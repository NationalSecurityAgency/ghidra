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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class Ext4XattrEntry implements StructConverter {
	
	private byte e_name_len;
	private byte e_name_index;
	private short e_value_offs;
	private int e_value_block;
	private int e_value_size;
	private int e_hash;
	private byte[] e_name;

	public Ext4XattrEntry(ByteProvider provider) throws IOException {
		this( new BinaryReader( provider, true ) );
	}
	
	public Ext4XattrEntry(BinaryReader reader) throws IOException {
		e_name_len = reader.readNextByte();
		e_name_index = reader.readNextByte();
		e_value_offs = reader.readNextShort();
		e_value_block = reader.readNextInt();
		e_value_size = reader.readNextInt();
		e_hash = reader.readNextInt();
		e_name = reader.readNextByteArray(e_name_len);
	}
	
	public byte getE_name_len() {
		return e_name_len;
	}

	public byte getE_name_index() {
		return e_name_index;
	}

	public short getE_value_offs() {
		return e_value_offs;
	}

	public int getE_value_block() {
		return e_value_block;
	}

	public int getE_value_size() {
		return e_value_size;
	}

	public int getE_hash() {
		return e_hash;
	}

	public byte[] getE_name() {
		return e_name;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("ext4_xattr_entry", 0);
		structure.add(BYTE, "e_name_len", null);
		structure.add(BYTE, "e_name_index", null);
		structure.add(WORD, "e_value_offs", null);
		structure.add(DWORD, "e_value_block", null);
		structure.add(DWORD, "e_value_size", null);
		structure.add(DWORD, "e_hash", null);
		structure.add( new ArrayDataType(BYTE, e_name_len, BYTE.getLength()), "e_name", null);
		return structure;
	}

}
