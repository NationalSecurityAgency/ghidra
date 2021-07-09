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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class Ext4GroupDescriptor implements StructConverter {
	
	private int bg_block_bitmap_lo;
	private int bg_inode_bitmap_lo;
	private int bg_inode_table_lo;
	private short bg_free_blocks_count_lo;
	private short bg_free_inodes_count_lo;
	private short bg_used_dirs_count_lo;
	private short bg_flags;
	private int bg_exclude_bitmap_lo;
	private short bg_block_bitmap_csum_lo;
	private short bg_inode_bitmap_csum_lo;
	private short bg_itable_unused_lo;
	private short bg_checksum;
	// These fields only exist if the 64bit feature is enabled and s_desc_size > 32.
	private int bg_block_bitmap_hi;
	private int bg_inode_bitmap_hi;
	private int bg_inode_table_hi;
	private short bg_free_blocks_count_hi;
	private short bg_free_inodes_count_hi;
	private short bg_used_dirs_count_hi;
	private short bg_itable_unused_hi;
	private int bg_exclude_bitmap_hi;
	private short bg_block_bitmap_csum_hi;
	private short bg_inode_bitmap_csum_hi;
	private int bg_reserved;
	
	private boolean is64Bit;

	public Ext4GroupDescriptor( ByteProvider provider, boolean is64Bit ) throws IOException {
		this( new BinaryReader( provider, true ), is64Bit );
	}
	
	public Ext4GroupDescriptor( BinaryReader reader, boolean is64Bit ) throws IOException {
		this.is64Bit = is64Bit;
		
		bg_block_bitmap_lo = reader.readNextInt();
		bg_inode_bitmap_lo = reader.readNextInt();
		bg_inode_table_lo = reader.readNextInt();
		bg_free_blocks_count_lo = reader.readNextShort();
		bg_free_inodes_count_lo = reader.readNextShort();
		bg_used_dirs_count_lo = reader.readNextShort();
		bg_flags = reader.readNextShort();
		bg_exclude_bitmap_lo = reader.readNextInt();
		bg_block_bitmap_csum_lo = reader.readNextShort();
		bg_inode_bitmap_csum_lo = reader.readNextShort();
		bg_itable_unused_lo = reader.readNextShort();
		bg_checksum = reader.readNextShort();
		if( !this.is64Bit ) {
			return;
		}
		bg_block_bitmap_hi = reader.readNextInt();
		bg_inode_bitmap_hi = reader.readNextInt();
		bg_inode_table_hi = reader.readNextInt();
		bg_free_blocks_count_hi = reader.readNextShort();
		bg_free_inodes_count_hi = reader.readNextShort();
		bg_used_dirs_count_hi = reader.readNextShort();
		bg_itable_unused_hi = reader.readNextShort();
		bg_exclude_bitmap_hi = reader.readNextInt();
		bg_block_bitmap_csum_hi = reader.readNextShort();
		bg_inode_bitmap_csum_hi = reader.readNextShort();
		bg_reserved = reader.readNextInt();
	}
	
	public int getBg_block_bitmap_lo() {
		return bg_block_bitmap_lo;
	}

	public int getBg_inode_bitmap_lo() {
		return bg_inode_bitmap_lo;
	}

	public int getBg_inode_table_lo() {
		return bg_inode_table_lo;
	}

	public short getBg_free_blocks_count_lo() {
		return bg_free_blocks_count_lo;
	}

	public short getBg_free_inodes_count_lo() {
		return bg_free_inodes_count_lo;
	}

	public short getBg_used_dirs_count_lo() {
		return bg_used_dirs_count_lo;
	}

	public short getBg_flags() {
		return bg_flags;
	}

	public int getBg_exclude_bitmap_lo() {
		return bg_exclude_bitmap_lo;
	}

	public short getBg_block_bitmap_csum_lo() {
		return bg_block_bitmap_csum_lo;
	}

	public short getBg_inode_bitmap_csum_lo() {
		return bg_inode_bitmap_csum_lo;
	}

	public short getBg_itable_unused_lo() {
		return bg_itable_unused_lo;
	}

	public short getBg_checksum() {
		return bg_checksum;
	}

	public int getBg_block_bitmap_hi() {
		return bg_block_bitmap_hi;
	}

	public int getBg_inode_bitmap_hi() {
		return bg_inode_bitmap_hi;
	}

	public int getBg_inode_table_hi() {
		return bg_inode_table_hi;
	}

	/**
	 * Return the calculated inode table value by combining bg_inode_table_lo and bg_inode_table_hi
	 * @return the calculated inode table value by combining bg_inode_table_lo and bg_inode_table_hi
	 */
	public long getBg_inode_table() {
		return ((long) bg_inode_table_hi << 32) | Integer.toUnsignedLong(bg_inode_table_lo);
	}

	public short getBg_free_blocks_count_hi() {
		return bg_free_blocks_count_hi;
	}

	public short getBg_free_inodes_count_hi() {
		return bg_free_inodes_count_hi;
	}

	public short getBg_used_dirs_count_hi() {
		return bg_used_dirs_count_hi;
	}

	public short getBg_itable_unused_hi() {
		return bg_itable_unused_hi;
	}

	public int getBg_exclude_bitmap_hi() {
		return bg_exclude_bitmap_hi;
	}

	public short getBg_block_bitmap_csum_hi() {
		return bg_block_bitmap_csum_hi;
	}

	public short getBg_inode_bitmap_csum_hi() {
		return bg_inode_bitmap_csum_hi;
	}

	public int getBg_reserved() {
		return bg_reserved;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("ext4_group_desc", 0);
		structure.add(DWORD, "bg_block_bitmap_lo", null);
		structure.add(DWORD, "bg_inode_bitmap_lo", null);
		structure.add(DWORD, "bg_inode_table_lo", null);
		structure.add(WORD, "bg_free_blocks_count_lo", null);
		structure.add(WORD, "bg_free_inodes_count_lo", null);
		structure.add(WORD, "bg_used_dirs_count_lo", null);
		structure.add(WORD, "bg_flags", null);
		structure.add(DWORD, "bg_exclude_bitmap_lo", null);
		structure.add(WORD, "bg_block_bitmap_csum_lo", null);
		structure.add(WORD, "bg_inode_bitmap_csum_lo", null);
		structure.add(WORD, "bg_itable_unused_lo", null);
		structure.add(WORD, "bg_checksum", null);
		if( is64Bit ) {
			structure.add(DWORD, "bg_block_bitmap_hi", null);
			structure.add(DWORD, "bg_inode_bitmap_hi", null);
			structure.add(DWORD, "bg_inode_table_hi", null);
			structure.add(WORD, "bg_free_blocks_count_hi", null);
			structure.add(WORD, "bg_free_inodes_count_hi", null);
			structure.add(WORD, "bg_used_dirs_count_hi", null);
			structure.add(WORD, "bg_itable_unused_hi", null);
			structure.add(DWORD, "bg_exclude_bitmap_hi", null);
			structure.add(WORD, "bg_block_bitmap_csum_hi", null);
			structure.add(WORD, "bg_inode_bitmap_csum_hi", null);
			structure.add(DWORD, "bg_reserved", null);
		}
		return structure;
	}

}
