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

public class Ext4Inode implements StructConverter {
	
	private short i_mode;
	private short i_uid;
	private int i_size_lo;
	private int i_atime;
	private int i_ctime;
	private int i_mtime;
	private int i_dtime;
	private short i_gid;
	private short i_links_count;
	private int i_blocks_lo;
	private int i_flags;
	private int i_osd1;
	private Ext4IBlock i_block; //15 ints long
	private int i_generation;
	private int i_file_acl_lo;
	private int i_size_high;
	private int i_obso_faddr;
	private byte[] i_osd2; //12 bytes long
	private short i_extra_isize;
	private short i_checksum_hi;
	private int i_ctime_extra;
	private int i_mtime_extra;
	private int i_atime_extra;
	private int i_crtime;
	private int i_crtime_extra;
	private int i_version_hi;
	private int i_projid;
	
	public Ext4Inode( ByteProvider provider ) throws IOException {
		this( new BinaryReader( provider, true ) );
	}
	
	public Ext4Inode( BinaryReader reader ) throws IOException {
		i_mode = reader.readNextShort();
		i_uid = reader.readNextShort();
		i_size_lo = reader.readNextInt();
		i_atime = reader.readNextInt();
		i_ctime = reader.readNextInt();
		i_mtime = reader.readNextInt();
		i_dtime = reader.readNextInt();
		i_gid = reader.readNextShort();
		i_links_count = reader.readNextShort();
		i_blocks_lo = reader.readNextInt();
		i_flags = reader.readNextInt();
		i_osd1 = reader.readNextInt();
		i_block = new Ext4IBlock(reader, (i_flags & 0x80000) != 0 );
		i_generation = reader.readNextInt();
		i_file_acl_lo = reader.readNextInt();
		i_size_high = reader.readNextInt();
		i_obso_faddr = reader.readNextInt();
		i_osd2 = reader.readNextByteArray(12); //12 bytes long
		i_extra_isize = reader.readNextShort();
		i_checksum_hi = reader.readNextShort();
		i_ctime_extra = reader.readNextInt();
		i_mtime_extra = reader.readNextInt();
		i_atime_extra = reader.readNextInt();
		i_crtime = reader.readNextInt();
		i_crtime_extra = reader.readNextInt();
		i_version_hi = reader.readNextInt();
		i_projid = reader.readNextInt();
	}

	
	public short getI_mode() {
		return i_mode;
	}

	public short getI_uid() {
		return i_uid;
	}

	public int getI_size_lo() {
		return i_size_lo;
	}

	public int getI_atime() {
		return i_atime;
	}

	public int getI_ctime() {
		return i_ctime;
	}
	
	public int getI_mtime() {
		return i_mtime;
	}

	public int getI_dtime() {
		return i_dtime;
	}

	public short getI_gid() {
		return i_gid;
	}

	public short getI_links_count() {
		return i_links_count;
	}

	public int getI_blocks_lo() {
		return i_blocks_lo;
	}

	public int getI_flags() {
		return i_flags;
	}

	public int getI_osd1() {
		return i_osd1;
	}

	public Ext4IBlock getI_block() {
		return i_block;
	}

	public int getI_generation() {
		return i_generation;
	}

	public int getI_file_acl_lo() {
		return i_file_acl_lo;
	}

	public int getI_size_high() {
		return i_size_high;
	}

	public int getI_obso_faddr() {
		return i_obso_faddr;
	}

	public byte[] getI_osd2() {
		return i_osd2;
	}

	public short getI_extra_isize() {
		return i_extra_isize;
	}

	public short getI_checksum_hi() {
		return i_checksum_hi;
	}

	public int getI_ctime_extra() {
		return i_ctime_extra;
	}

	public int getI_mtime_extra() {
		return i_mtime_extra;
	}

	public int getI_atime_extra() {
		return i_atime_extra;
	}

	public int getI_crtime() {
		return i_crtime;
	}

	public int getI_crtime_extra() {
		return i_crtime_extra;
	}

	public int getI_version_hi() {
		return i_version_hi;
	}

	public int getI_projid() {
		return i_projid;
	}

	/**
	 * Returns the size of this file.
	 * 
	 * @return size of this file
	 */
	public long getSize() {
		return Integer.toUnsignedLong(i_size_high) << 32 | Integer.toUnsignedLong(i_size_lo);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		DataType iBlockDataType = i_block.toDataType();
		Structure structure = new StructureDataType("ext4_inode_"+iBlockDataType.getName( ), 0);
		structure.add(WORD, "i_mode", null);
		structure.add(WORD, "i_uid", null);
		structure.add(DWORD, "i_size_lo", null);
		structure.add(DWORD, "i_atime", null);
		structure.add(DWORD, "i_ctime", null);
		structure.add(DWORD, "i_mtime", null);
		structure.add(DWORD, "i_dtime", null);
		structure.add(WORD, "i_gid", null);
		structure.add(WORD, "i_links_count", null);
		structure.add(DWORD, "i_blocks_lo", null);
		structure.add(DWORD, "i_flags", null);
		structure.add(DWORD, "i_osd1", null);
		structure.add(iBlockDataType, "i_block", null);
		structure.add(DWORD, "i_generation", null);
		structure.add(DWORD, "i_file_acl_lo", null);
		structure.add(DWORD, "i_size_high", null);
		structure.add(DWORD, "i_obso_faddr", null);
		structure.add(new ArrayDataType(BYTE, 12, BYTE.getLength()), "i_osd2", null); //12 bytes long
		structure.add(WORD, "i_extra_isize", null);
		structure.add(WORD, "i_checksum_hi", null);
		structure.add(DWORD, "i_ctime_extra", null);
		structure.add(DWORD, "i_mtime_extra", null);
		structure.add(DWORD, "i_atime_extra", null);
		structure.add(DWORD, "i_crtime", null);
		structure.add(DWORD, "i_crtime_extra", null);
		structure.add(DWORD, "i_version_hi", null);
		structure.add(DWORD, "i_projid", null);
		return structure;
	}

}
