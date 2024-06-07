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
package ghidra.file.formats.squashfs;

public final class SquashConstants {

	// SquashFS magic bytes ("hsqs")
	public static final byte[] MAGIC = { 0x68, 0x73, 0x71, 0x73 };

	/**
	 * Compression types
	 */
	public static final int COMPRESSION_TYPE_GZIP = 1;
	public static final int COMPRESSION_TYPE_LZMA = 2;
	public static final int COMPRESSION_TYPE_LZO = 3;
	public static final int COMPRESSION_TYPE_XZ = 4;
	public static final int COMPRESSION_TYPE_LZ4 = 5;
	public static final int COMPRESSION_TYPE_ZSTD = 6;

	/*
	 * Superblock flag masks
	 */
	public static final int UNCOMPRESSED_INODES = 0x0001;
	public static final int UNCOMPRESSED_DATA_BLOCKS = 0x0002;
	public static final int UNUSED_FLAG = 0x0004;
	public static final int UNCOMPRESSED_FRAGMENTS = 0x0008;
	public static final int NO_FRAGMENTS = 0x0010;
	public static final int ALWAYS_FRAGMENT = 0x0020;
	public static final int NO_DUPLICATE_DATE = 0x0040;
	public static final int EXPORT_TABLE_EXISTS = 0x0080;
	public static final int UNCOMPRESSED_XATTRS = 0x0100;
	public static final int NO_XATTRS = 0x0200;
	public static final int COMPRESSION_OPTIONS_EXIST = 0x0400;
	public static final int UNCOMPRESSED_IDS = 0x0800;

	/**
	 * Inode Types
	 */
	public static final int INODE_TYPE_BASIC_DIRECTORY = 0x01;
	public static final int INODE_TYPE_BASIC_FILE = 0x02;
	public static final int INODE_TYPE_BASIC_SYMLINK = 0x03;
	public static final int INODE_TYPE_BASIC_BLOCK_DEVICE = 0x04;
	public static final int INODE_TYPE_BASIC_CHAR_DEVICE = 0x05;
	public static final int INODE_TYPE_BASIC_FIFO = 0x06;
	public static final int INODE_TYPE_BASIC_SOCKET = 0x07;
	public static final int INODE_TYPE_EXTENDED_DIRECTORY = 0x08;
	public static final int INODE_TYPE_EXTENDED_FILE = 0x09;
	public static final int INODE_TYPE_EXTENDED_SYMLINK = 0x0A;
	public static final int INODE_TYPE_EXTENDED_BLOCK_DEVICE = 0x0B;
	public static final int INODE_TYPE_EXTENDED_CHAR_DEVICE = 0x0C;
	public static final int INODE_TYPE_EXTENDED_FIFO = 0x0D;
	public static final int INODE_TYPE_EXTENDED_SOCKET = 0x0E;

	/**
	 * Data sizes
	 */
	public static final int MAX_UNIT_BLOCK_SIZE = 0x2000; // 8192 bytes = 8KiB
	public static final int FRAGMENT_ENTRY_LENGTH = 16;
	public static final int MAX_SYMLINK_DEPTH = 100;

	/**
	 * General bit masks
	 */
	// In the superblock, all bits are set for a reference to an omitted section
	public static final int SECTION_OMITTED = 0xFFFFFFFF;

	// If an inode's file index has all bits set, it indicates there are no associated fragments
	public static final int INODE_NO_FRAGMENTS = 0xFFFFFFFF;

	// Used to find if a fragment is compressed from its "size" header (25th bit is set)
	// Will be inverted to mask out the size
	public static final int FRAGMENT_COMPRESSED_MASK = 1 << 24;

	// Used to find if a data block is compressed from its "size" header (25th bit is set)
	// Will be inverted to mask out the size
	public static final int DATABLOCK_COMPRESSED_MASK = 1 << 24;

	// Used to find if a data block is compressed from its "size" header (
	// Will be inverted to mask out the size
	public static final int METABLOCK_UNCOMPRESSED_MASK = 1 << 15;
}
