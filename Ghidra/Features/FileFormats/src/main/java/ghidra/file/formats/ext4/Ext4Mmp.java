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

public class Ext4Mmp implements StructConverter {
	
	private int mmp_magic;
	private int mmp_seq;
	private long mmp_time;
	private byte[] mmp_nodename; //64 bytes long.
	private byte[] mmp_bdevname; //32 bytes long.
	private short mmp_check_interval;
	private short mmp_pad1;
	private int[] mmp_pad2; //226 ints long.
	private int mmp_checksum;
	
	public Ext4Mmp(ByteProvider provider) throws IOException {
		this( new BinaryReader( provider, true ) );
	}

	public Ext4Mmp(BinaryReader reader) throws IOException {
		mmp_magic = reader.readNextInt();
		mmp_seq = reader.readNextInt();
		mmp_time = reader.readNextLong();
		mmp_nodename = reader.readNextByteArray(64);
		mmp_bdevname = reader.readNextByteArray(32);
		mmp_check_interval = reader.readNextShort();
		mmp_pad1 = reader.readNextShort();
		mmp_pad2 = reader.readNextIntArray(226);
		mmp_checksum = reader.readNextInt();
	}
	
	public int getMmp_magic() {
		return mmp_magic;
	}

	public int getMmp_seq() {
		return mmp_seq;
	}

	public long getMmp_time() {
		return mmp_time;
	}

	public byte[] getMmp_nodename() {
		return mmp_nodename;
	}

	public byte[] getMmp_bdevname() {
		return mmp_bdevname;
	}

	public short getMmp_check_interval() {
		return mmp_check_interval;
	}

	public short getMmp_pad1() {
		return mmp_pad1;
	}

	public int[] getMmp_pad2() {
		return mmp_pad2;
	}

	public int getMmp_checksum() {
		return mmp_checksum;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("mmp_struct", 0);
		structure.add(DWORD, "mmp_magic", null);
		structure.add(DWORD, "mmp_seq", null);
		structure.add(QWORD, "mmp_time", null);
		structure.add( new ArrayDataType( BYTE, 64, BYTE.getLength()), "mmp_nodename", null); //64 bytes long.
		structure.add( new ArrayDataType( BYTE, 32, BYTE.getLength()), "mmp_bdevname", null); //32 bytes long.
		structure.add(WORD, "mmp_check_interval", null);
		structure.add(WORD, "mmp_pad1", null);
		structure.add( new ArrayDataType(DWORD, 226, DWORD.getLength()), "mmp_pad2", null);
		structure.add(DWORD, "mmp_checksum", null);
		return structure;
	}

}
