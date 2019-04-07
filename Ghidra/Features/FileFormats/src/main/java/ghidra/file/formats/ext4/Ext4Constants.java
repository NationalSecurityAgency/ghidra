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

public final class Ext4Constants {
	
	public final static int SUPER_BLOCK_MAGIC = 0xEF53;
	
	//Super Block Compatible Feature Flags
	public final static int COMPAT_DIR_PREALLOC = 0x1;
	public final static int COMPAT_IMAGIC_INODES = 0x2;
	public final static int COMPAT_HAS_JOURNAL = 0x4;
	public final static int COMPAT_EXT_ATTR = 0x8;
	public final static int COMPAT_RESIZE_INODE = 0x10;
	public final static int COMPAT_DIR_INDEX = 0x20;
	public final static int COMPAT_LAZY_BG = 0x40;
	public final static int COMPAT_EXCLUDE_INODE = 0x80;
	public final static int COMPAT_EXCLUDE_BITMAP = 0x100;
	public final static int COMPAT_SPARSE_SUPER2 = 0x200;
	
	//Super Block Incompatible Feature Flags
	public final static int INCOMPAT_COMPRESSION = 0x1;
	public final static int INCOMPAT_FILETYPE = 0x2;
	public final static int INCOMPAT_RECOVER = 0x4;
	public final static int INCOMPAT_JOURNAL_DEV = 0x8;
	public final static int INCOMPAT_META_BG = 0x10;
	public final static int INCOMPAT_EXTENTS = 0x40;
	public final static int INCOMPAT_64BIT = 0x80;
	public final static int INCOMPAT_MMP = 0x100;
	public final static int INCOMPAT_FLEX_BG = 0x200;
	public final static int INCOMPAT_EA_INODE = 0x400;
	public final static int INCOMPAT_DIRDATA = 0x1000;
	public final static int INCOMPAT_CSUM_SEED = 0x2000;
	public final static int INCOMPAT_LARGEDIR = 0x4000;
	public final static int INCOMPAT_INLINE_DATA = 0x8000;
	public final static int INCOMPAT_ENCRYPT = 0x10000;
	
	//Super Block Read-only Compatible Feature Flags
	public final static int RO_COMPAT_SPARSE_SUPER = 0x1;
	public final static int RO_COMPAT_LARGE_FILE = 0x2;
	public final static int RO_COMPAT_BTREE_DIR = 0x4;
	public final static int RO_COMPAT_HUGE_FILE = 0x8;
	public final static int RO_COMPAT_GDT_CSUM = 0x10;
	public final static int RO_COMPAT_DIR_NLINK = 0x20;
	public final static int RO_COMPAT_EXTRA_ISIZE = 0x40;
	public final static int RO_COMPAT_HAS_SNAPSHOT = 0x80;
	public final static int RO_COMPAT_QUOTA = 0x100;
	public final static int RO_COMPAT_BIGALLOC = 0x200;
	public final static int RO_COMPAT_METADATA_CSUM = 0x400;
	public final static int RO_COMPAT_REPLICA = 0x800;
	public final static int RO_COMPAT_READONLY = 0x1000;
	public final static int RO_COMPAT_PROJECT = 0x2000;
	
	//Inode File Mode
	public final static int S_IXOTH = 0x1;
	public final static int S_IWOTH = 0x2;
	public final static int S_IROTH = 0x4;
	public final static int S_IXGRP = 0x8;
	public final static int S_IWGRP = 0x10;
	public final static int S_IRGRP = 0x20;
	public final static int S_IXUSR = 0x40;
	public final static int S_IWUSR = 0x80;
	public final static int S_IRUSR = 0x100;
	public final static int S_ISVTX = 0x200;
	public final static int S_ISGID = 0x400;
	public final static int S_ISUID = 0x800;
	//These are mutually-exclusive file types
	public final static int S_IFIFO = 0x1000;
	public final static int S_IFCHR = 0x2000;
	public final static int S_IFDIR = 0x4000;
	public final static int S_IFBLK = 0x6000;
	public final static int S_IFREG = 0x8000;
	public final static int S_IFLNK = 0xA000;
	public final static int S_IFSOCK = 0xC000;
	
	public final static int I_MODE_MASK = 0xF000;
	
	//Inode Flags
	public final static int EXT4_SECRM_FL = 0x1;
	public final static int EXT4_UNRM_FL = 0x2;
	public final static int EXT4_COMPR_FL = 0x4;
	public final static int EXT4_SYNC_FL = 0x8;
	public final static int EXT4_IMMUTABLE_FL = 0x10;
	public final static int EXT4_APPEND_FL = 0x20;
	public final static int EXT4_NODUMP_FL = 0x40;
	public final static int EXT4_NOATIME_FL = 0x80;
	public final static int EXT4_DIRTY_FL = 0x100;
	public final static int EXT4_COMPRBLK_FL = 0x200;
	public final static int EXT4_NOCOMPR_FL = 0x400;
	public final static int EXT4_ENCRYPT_FL = 0x800;
	public final static int EXT4_INDEX_FL = 0x1000;
	public final static int EXT4_IMAGIC_FL = 0x2000;
	public final static int EXT4_JOURNAL_DATA_FL = 0x4000;
	public final static int EXT4_NOTAIL_FL = 0x8000;
	public final static int EXT4_DIRSYNC_FL = 0x10000;
	public final static int EXT4_TOPDIR_FL = 0x20000;
	public final static int EXT4_HUGE_FILE_FL = 0x40000;
	public final static int EXT4_EXTENTS_FL = 0x80000;
	public final static int EXT4_EA_INODE_FL = 0x200000;
	public final static int EXT4_EOFBLOCKS_FL = 0x400000;
	public final static int EXT4_SNAPFILE_FL = 0x01000000;
	public final static int EXT4_SNAPFILE_DELETED_FL = 0x04000000;
	public final static int EXT4_SNAPFILE_SHRUNK_FL = 0x08000000;
	public final static int EXT4_INLINE_DATA_FL = 0x10000000;
	public final static int EXT4_PROJINHERIT_FL = 0x20000000;
	public final static int EXT4_RESERVED_FL = 0x80000000;

	public final static int EXTENT_HEADER_MAGIC = 0xF30A;

	// ------------------------------------------------------
	// ext4_dir_entry_2 File Types
	
	public final static byte FILE_TYPE_UNKNOWN = 0x0;
	public final static byte FILE_TYPE_REGULAR_FILE = 0x1;
	public final static byte FILE_TYPE_DIRECTORY = 0x2;
	public final static byte FILE_TYPE_CHARACTER_DEVICE_FILE = 0x3;
	public final static byte FILE_TYPE_BLOCK_DEVICE_FILE = 0x4;
	public final static byte FILE_TYPE_FIFO = 0x5;
	public final static byte FILE_TYPE_SOCKET = 0x6;
	public final static byte FILE_TYPE_SYMBOLIC_LINK = 0x7;

	// ------------------------------------------------------

	/**
	 * @see https://github.com/torvalds/linux/blob/master/fs/ext4/ext4.h
	 * 
	 * Ext4 directory file types.  Only the low 3 bits are used.  The
	 * other bits are reserved for now.
	 */
	public final static byte EXT4_FT_UNKNOWN   = 0;
	public final static byte EXT4_FT_REG_FILE  = 1;
	public final static byte EXT4_FT_DIR       = 2;
	public final static byte EXT4_FT_CHRDEV    = 3;
	public final static byte EXT4_FT_BLKDEV    = 4;
	public final static byte EXT4_FT_FIFO      = 5;
	public final static byte EXT4_FT_SOCK      = 6;
	public final static byte EXT4_FT_SYMLINK   = 7;

	public final static byte EXT4_FT_MAX       = 8;

	public final static byte EXT4_FT_DIR_CSUM  = (byte) 0xDE;
}
