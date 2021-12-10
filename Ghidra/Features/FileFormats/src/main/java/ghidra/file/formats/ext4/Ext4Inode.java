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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class Ext4Inode implements StructConverter {
	private static final int INODE_BASE_SIZE = 128;	// by definition
	private static final int MINIMAL_SIZEOF_INODE = 0xa0; // sizeof the fields we try to read

	//@formatter:off
	//                                     Offset (hex) Length  Comment
	private short i_mode;               // 0            2       see Ext4Constants.S_IXOTH...S_IFSOCK
	private short i_uid;                // 2            2
	private int i_size_lo;              // 4            4
	private int i_atime;                // 8            4
	private int i_ctime;                // C            4
	private int i_mtime;                // 10           4
	private int i_dtime;                // 14           4
	private short i_gid;                // 18           2
	private short i_links_count;        // 1A           2
	private int i_blocks_lo;            // 1C           4
	private int i_flags;                // 20           4        see Ext4Constants.EXT4_SECRM_FL...EXT4_RESERVED_FL
	private int i_osd1;                 // 24           4
	private byte[] i_block;             // 28           60
	private int i_generation;           // 64           4
	private int i_file_acl_lo;          // 68           4
	private int i_size_high;            // 6C           4
	private int i_obso_faddr;           // 70           4
	private byte[] i_osd2;              // 74           12       last of the base fields, everything after is counted in i_extra_isize
	private short i_extra_isize;        // 80           2        number of bytes to the end of the defined fields
	private short i_checksum_hi;        // 82           2
	private int i_ctime_extra;          // 84           4
	private int i_mtime_extra;          // 88           4
	private int i_atime_extra;          // 8C           4
	private int i_crtime;               // 90           4
	private int i_crtime_extra;         // 94           4
	private int i_version_hi;           // 98           4
	private int i_projid;               // 9C           4
	//unknown_fields                    // A0           i_extra_isize-32           
	//extended_attributes               // 80+i_extra_size, inodeSize-0x80-i_extra_isize
	//@formatter:on

	private Ext4Xattributes xAttributes;

	public Ext4Inode(BinaryReader reader) throws IOException {
		this(reader, MINIMAL_SIZEOF_INODE);
	}
	
	public Ext4Inode(BinaryReader reader, int inodeSize) throws IOException {
		if (inodeSize < INODE_BASE_SIZE) {
			throw new IOException("Bad inodeSize: " + inodeSize);
		}
		long inodeStart = reader.getPointerIndex();
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
		i_block = reader.readNextByteArray(60);
		i_generation = reader.readNextInt();
		i_file_acl_lo = reader.readNextInt();
		i_size_high = reader.readNextInt();
		i_obso_faddr = reader.readNextInt();
		i_osd2 = reader.readNextByteArray(12); //12 bytes long
		if (inodeSize > INODE_BASE_SIZE) {
			i_extra_isize = reader.readNextShort();
			i_checksum_hi = reader.readNextShort();
			i_ctime_extra = reader.readNextInt();
			i_mtime_extra = reader.readNextInt();
			i_atime_extra = reader.readNextInt();
			i_crtime = reader.readNextInt();
			i_crtime_extra = reader.readNextInt();
			i_version_hi = reader.readNextInt();
			i_projid = reader.readNextInt();

			// skipping unknown fields here

			// read EAs if present
			reader.setPointerIndex(inodeStart + INODE_BASE_SIZE + i_extra_isize);
			xAttributes = Ext4Xattributes.readInodeXAttributes(reader, inodeStart + inodeSize);
		}
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

	public byte[] getI_block() {
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

	/**
	 * Returns true if the inode appears to be unused.
	 *  
	 * @return boolean true if the inode appears to be unused
	 */
	public boolean isUnused() {
		return i_links_count == 0;
	}

	public boolean isSymLink() {
		return (i_mode & Ext4Constants.I_MODE_MASK) == Ext4Constants.S_IFLNK;
	}

	public boolean isFile() {
		return (i_mode & Ext4Constants.I_MODE_MASK) == Ext4Constants.S_IFREG;
	}

	public boolean isDir() {
		return (i_mode & Ext4Constants.I_MODE_MASK) == Ext4Constants.S_IFDIR;
	}

	public int getFileType() {
		return i_mode & Ext4Constants.I_MODE_MASK;
	}

	public boolean isFlagExtents() {
		return (i_flags & Ext4Constants.EXT4_EXTENTS_FL) != 0;
	}

	public boolean isFlagInlineData() {
		return (i_flags & Ext4Constants.EXT4_INLINE_DATA_FL) != 0;
	}

	/**
	 * Returns the bytes in this inode's i_block and the "system.data"
	 * extended attribute.
	 * 
	 * @return bytes of this file that were stored inline in the inode
	 * @throws IOException if not able to assemble enough bytes to match
	 * the file size
	 */
	public byte[] getInlineDataValue() throws IOException {
		int bytesRemaining = (int) getSize();
		byte[] result = new byte[bytesRemaining];
		byte[] eaSystemData = getEAValue("system.data");
		if (eaSystemData == null) {
			eaSystemData = new byte[0];
		}
		int bytesCopied = 0;
		int copyLen = Math.min(bytesRemaining, i_block.length);
		System.arraycopy(i_block, 0, result, 0, copyLen);
		bytesCopied += copyLen;
		bytesRemaining -= copyLen;
		if (bytesRemaining > 0) {
			copyLen = Math.min(bytesRemaining, eaSystemData.length);
			System.arraycopy(eaSystemData, 0, result, bytesCopied, copyLen);
			bytesCopied += copyLen;
			bytesRemaining -= copyLen;
		}
		if (bytesRemaining != 0) {
			throw new IOException("Unable to read inline data");
		}
		return result;
	}

	byte[] getEAValue(String name) {
		Ext4XattrEntry attr = (xAttributes != null) ? xAttributes.getAttribute(name) : null;
		return attr != null ? attr.getValue() : null;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("ext4_inode", 0);
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
		structure.add(new ArrayDataType(BYTE, 60, BYTE.getLength()), "i_block", null);
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
