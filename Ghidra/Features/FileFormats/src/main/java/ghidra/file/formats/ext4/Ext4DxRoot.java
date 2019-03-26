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

public class Ext4DxRoot implements StructConverter {

	private int dot_inode;
	private short dot_rec_len;
	private byte dot_name_len;
	private byte dot_file_type;
	private byte[] dot_name;
	private int dotdot_inode;
	private short dotdot_rec_len;
	private byte dotdot_name_len;
	private byte dotdot_file_type;
	private byte[] dotdot_name;
	private int dx_root_info_reserved_zero;
	private byte dx_root_info_hash_version;
	private byte dx_root_info_info_length;
	private byte dx_root_info_indirect_levels;
	private byte dx_root_info_unused_flags; 	
	private short limit;
	private short count;
	private int block;
	private Ext4DxEntry[] entries; 
	
	public Ext4DxRoot(ByteProvider provider) throws IOException {
		this( new BinaryReader( provider, true ) );
	}
	
	public Ext4DxRoot(BinaryReader reader) throws IOException {
		dot_inode = reader.readNextInt();
		dot_rec_len = reader.readNextShort();
		dot_name_len = reader.readNextByte();
		dot_file_type = reader.readNextByte();
		dot_name = reader.readNextByteArray(4);
		dotdot_inode = reader.readNextInt();
		dotdot_rec_len = reader.readNextShort();
		dotdot_name_len = reader.readNextByte();
		dotdot_file_type = reader.readNextByte();
		dotdot_name = reader.readNextByteArray(4);
		dx_root_info_reserved_zero = reader.readNextInt();
		dx_root_info_hash_version = reader.readNextByte();
		dx_root_info_info_length = reader.readNextByte();
		dx_root_info_indirect_levels = reader.readNextByte();
		dx_root_info_unused_flags = reader.readNextByte(); 	
		limit = reader.readNextShort();
		count = reader.readNextShort();
		block = reader.readNextInt();
		entries = new Ext4DxEntry[count];
		for( int i = 0; i < count; i++ ) {
			entries[i] = new Ext4DxEntry(reader);
		}
	}
	
	public int getDot_inode() {
		return dot_inode;
	}

	public short getDot_rec_len() {
		return dot_rec_len;
	}

	public byte getDot_name_len() {
		return dot_name_len;
	}

	public byte getDot_file_type() {
		return dot_file_type;
	}

	public byte[] getDot_name() {
		return dot_name;
	}

	public int getDotdot_inode() {
		return dotdot_inode;
	}

	public short getDotdot_rec_len() {
		return dotdot_rec_len;
	}

	public byte getDotdot_name_len() {
		return dotdot_name_len;
	}

	public byte getDotdot_file_type() {
		return dotdot_file_type;
	}

	public byte[] getDotdot_name() {
		return dotdot_name;
	}

	public int getDx_root_info_reserved_zero() {
		return dx_root_info_reserved_zero;
	}

	public byte getDx_root_info_hash_version() {
		return dx_root_info_hash_version;
	}

	public byte getDx_root_info_info_length() {
		return dx_root_info_info_length;
	}

	public byte getDx_root_info_indirect_levels() {
		return dx_root_info_indirect_levels;
	}

	public byte getDx_root_info_unused_flags() {
		return dx_root_info_unused_flags;
	}

	public short getLimit() {
		return limit;
	}

	public short getCount() {
		return count;
	}

	public int getBlock() {
		return block;
	}

	public Ext4DxEntry[] getEntries() {
		return entries;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("dx_root", 0);
		structure.add(DWORD, "dot_inode", null);
		structure.add(WORD, "dot_rec_len", null);
		structure.add(BYTE, "dot_name_len", null);
		structure.add(BYTE, "dot_file_type", null);
		structure.add(new ArrayDataType(BYTE, 4, BYTE.getLength()), "dot_name", null);
		structure.add(DWORD, "dotdot_inode", null);
		structure.add(WORD, "dotdot_rec_len", null);
		structure.add(BYTE, "dotdot_name_len", null);
		structure.add(BYTE, "dotdot_file_type", null);
		structure.add(new ArrayDataType(BYTE, 4, BYTE.getLength()), "dotdot_name", null);
		structure.add(DWORD, "dx_root_info_reserved_zero", null);
		structure.add(BYTE, "dx_root_info_hash_version", null);
		structure.add(BYTE, "dx_root_info_info_length", null);
		structure.add(BYTE, "dx_root_info_indirect_levels", null);
		structure.add(BYTE, "dx_root_info_unused_flags", null); 	
		structure.add(WORD, "limit", null);
		structure.add(WORD, "count", null);
		structure.add(DWORD, "block", null);
		structure.add(new ArrayDataType(entries[0].toDataType(), count, entries[0].toDataType().getLength()), "entries", null); 
		return structure;
	}

}
