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

public class Ext4JournalSuperBlockS implements StructConverter {
	private Ext4JournalHeaderS s_header;
	//	Static information describing the journal.
	private int s_blocksize;
	private int s_maxlen;
	private int s_first;
	//	Dynamic information describing the current state of the log.
	private int s_sequence;
	private int s_start;
	private int s_errno;
	//	The remaining fields are only valid in a version 2 superblock.
	private int s_feature_compat;
	private int s_feature_incompat;
	private int s_feature_ro_compat;
	private byte[] s_uuid; //16 bytes long.
	private int s_nr_users;
	private int s_dynsuper;
	private int s_max_transaction;
	private int s_max_trans_data;
	private byte s_checksum_type;
	private byte[] s_padding2; //3 bytes long.
	private int[] s_padding; //42 ints long.
	private int s_checksum;
	private byte[] s_users; //768 (16*48) bytes long.
	
	public Ext4JournalSuperBlockS(ByteProvider provider) throws IOException {
		this( new BinaryReader( provider, false ) );
	}
	
	public Ext4JournalSuperBlockS(BinaryReader reader) throws IOException {
		// Journal is big-endian... opposite of the rest of the file.
		reader.setLittleEndian(false);
		
		s_header = new Ext4JournalHeaderS(reader);
		s_blocksize = reader.readNextInt();
		s_maxlen = reader.readNextInt();
		s_first = reader.readNextInt();
		s_sequence = reader.readNextInt();
		s_start = reader.readNextInt();
		s_errno = reader.readNextInt();
		s_feature_compat = reader.readNextInt();
		s_feature_incompat = reader.readNextInt();
		s_feature_ro_compat = reader.readNextInt();
		s_uuid = reader.readNextByteArray(16); //16 bytes long.
		s_nr_users = reader.readNextInt();
		s_dynsuper = reader.readNextInt();
		s_max_transaction = reader.readNextInt();
		s_max_trans_data = reader.readNextInt();
		s_checksum_type = reader.readNextByte();
		s_padding2 = reader.readNextByteArray(3); //3 bytes long.
		s_padding = reader.readNextIntArray(42); //42 ints long.
		s_checksum = reader.readNextInt();
		s_users = reader.readNextByteArray(768); //768 (16*48) bytes long.
	}
	
	public Ext4JournalHeaderS getS_header() {
		return s_header;
	}

	public int getS_blocksize() {
		return s_blocksize;
	}

	public int getS_maxlen() {
		return s_maxlen;
	}

	public int getS_first() {
		return s_first;
	}

	public int getS_sequence() {
		return s_sequence;
	}

	public int getS_start() {
		return s_start;
	}

	public int getS_errno() {
		return s_errno;
	}

	public int getS_feature_compat() {
		return s_feature_compat;
	}

	public int getS_feature_incompat() {
		return s_feature_incompat;
	}

	public int getS_feature_ro_compat() {
		return s_feature_ro_compat;
	}

	public byte[] getS_uuid() {
		return s_uuid;
	}

	public int getS_nr_users() {
		return s_nr_users;
	}

	public int getS_dynsuper() {
		return s_dynsuper;
	}

	public int getS_max_transaction() {
		return s_max_transaction;
	}

	public int getS_max_trans_data() {
		return s_max_trans_data;
	}

	public byte getS_checksum_type() {
		return s_checksum_type;
	}

	public byte[] getS_padding2() {
		return s_padding2;
	}

	public int[] getS_padding() {
		return s_padding;
	}

	public int getS_checksum() {
		return s_checksum;
	}

	public byte[] getS_users() {
		return s_users;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("journal_superblock_s", 0);
		structure.add(s_header.toDataType(), "s_header", null);
		structure.add(DWORD, "s_blocksize", null);
		structure.add(DWORD, "s_maxlen", null);
		structure.add(DWORD, "s_first", null);
		structure.add(DWORD, "s_sequence", null);
		structure.add(DWORD, "s_start", null);
		structure.add(DWORD, "s_errno", null);
		structure.add(DWORD, "s_feature_compat", null);
		structure.add(DWORD, "s_feature_incompat", null);
		structure.add(DWORD, "s_feature_ro_compat", null);
		structure.add(new ArrayDataType(BYTE, 16, BYTE.getLength()), "s_uuid", null); //16 bytes long.
		structure.add(DWORD, "s_nr_users", null);
		structure.add(DWORD, "s_dynsuper", null);
		structure.add(DWORD, "s_max_transaction", null);
		structure.add(DWORD, "s_max_trans_data", null);
		structure.add(BYTE, "s_checksum_type", null);
		structure.add(new ArrayDataType(BYTE, 3, BYTE.getLength()), "s_padding2", null); //3 bytes long.
		structure.add(new ArrayDataType(DWORD, 42, DWORD.getLength()), "s_padding", null); //42 ints long.
		structure.add(DWORD, "s_checksum", null);
		structure.add(new ArrayDataType(BYTE, 768, BYTE.getLength()), "s_users", null); //768 (16*48) bytes long.
		return structure;
	}

}
