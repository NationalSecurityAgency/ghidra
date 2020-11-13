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

public class Ext4SuperBlock implements StructConverter {

	private int s_inodes_count;
	private int s_blocks_count_lo;
	private int s_r_blocks_count_lo;
	private int s_free_blocks_count_lo;
	private int s_free_inodes_count;
	private int s_first_data_block;
	private int s_log_block_size;
	private int s_log_cluster_size;
	private int s_blocks_per_group;
	private int s_clusters_per_group;
	private int s_inodes_per_group;
	private int s_mtime;
	private int s_wtime;
	private short s_mnt_count;
	private short s_max_mnt_count;
	private short s_magic;
	private short s_state;
	private short s_errors;
	private short s_minor_rev_level;
	private int s_lastcheck;
	private int s_checkinterval;
	private int s_creator_os;
	private int s_rev_level;
	private short s_def_resuid;
	private short s_def_resgid;
	// For EXT4_DYNAMIC_REV superblocks only (s_rev_level == 1)
	private int s_first_ino;
	private short s_inode_size;
	private short s_block_group_nr;
	private int s_feature_compat;
	private int s_feature_incompat;
	private int s_feature_ro_compat;
	private byte[] s_uuid; //16 bytes long
	private byte[] s_volume_name; // 16 bytes long
	private byte[] s_last_mounted; // 64 bytes long
	private int s_algorithm_usage_bitmap;
	// Performance hints.  Directory preallocation should only happen if 
	// the EXT4_FEATURE_COMPAT_DIR_PREALLOC flag is on. (s_feature_compat & 0x1 != 0)
	private byte s_prealloc_blocks;
	private byte s_prealloc_dir_blocks;
	private short s_reserved_gdt_blocks;
	// Journaling support valid if EXT4_FEATURE_COMPAT_HAS_JOURNAL set. (s_feature_compat & 0x4 != 0)
	private byte[] s_journal_uuid; // 16 bytes long
	private int s_journal_inum;
	private int s_journal_dev;
	private int s_last_orphan;
	private int[] s_hash_seed; // 4 ints long
	private byte s_def_hash_version;
	private byte s_jnl_backup_type;
	private short s_desc_size;
	private int s_default_mount_opts;
	private int s_first_meta_bg;
	private int s_mkfs_time;
	private int[] s_jnl_blocks; // 17 ints long
	// 64bit support valid if EXT4_FEATURE_COMPAT_64BIT (s_feature_incompat & 0x80 != 0)
	private int s_blocks_count_hi;
	private int s_r_blocks_count_hi;
	private int s_free_blocks_count_hi;
	private short s_min_extra_isize;
	private short s_want_extra_isize;
	private int s_flags;
	private short s_raid_stride;
	private short s_mmp_interval;
	private long s_mmp_block;
	private int s_raid_stripe_width;
	private byte s_log_groups_per_flex;
	private byte s_checksum_type;
	private short s_reserved_pad;
	private long s_kbytes_written;
	private int s_snapshot_inum;
	private int s_snapshot_id;
	private long s_snapshot_r_blocks_count;
	private int s_snapshot_list;
	private int s_error_count;
	private int s_first_error_time;
	private int s_first_error_ino;
	private long s_first_error_block;
	private byte[] s_first_error_func; // 32 bytes long
	private int s_first_error_line;
	private int s_last_error_time;
	private int s_last_error_ino;
	private int s_last_error_line;
	private long s_last_error_block;
	private byte[] s_last_error_func; //32 bytes long
	private byte[] s_mount_opts; // 64 bytes long
	private int s_usr_quora_inum;
	private int s_grp_quota_inum;
	private int s_overhead_blocks;
	private int[] s_backup_blocks; // 2 ints long
	private byte[] s_encrypt_algos; // 4 bytes long
	private byte[] s_encrypt_pw_salt; // 16 bytes long
	private int s_lpf_ino;
	private int s_prj_quota_inum;
	private int s_checksum_seed;
	private int[] s_reserved; // 98 ints long
	private int s_checksum;
	
	public Ext4SuperBlock( ByteProvider provider ) throws IOException {
		this( new BinaryReader( provider, true ) );
	}
	
	public Ext4SuperBlock( BinaryReader reader ) throws IOException {
		s_inodes_count = reader.readNextInt();
		s_blocks_count_lo = reader.readNextInt();
		s_r_blocks_count_lo = reader.readNextInt();
		s_free_blocks_count_lo = reader.readNextInt();
		s_free_inodes_count = reader.readNextInt();
		s_first_data_block = reader.readNextInt();
		s_log_block_size = reader.readNextInt();
		s_log_cluster_size = reader.readNextInt();
		s_blocks_per_group = reader.readNextInt();
		s_clusters_per_group = reader.readNextInt();
		s_inodes_per_group = reader.readNextInt();
		s_mtime = reader.readNextInt();
		s_wtime = reader.readNextInt();
		s_mnt_count = reader.readNextShort();
		s_max_mnt_count = reader.readNextShort();
		s_magic = reader.readNextShort();
		s_state = reader.readNextShort();
		s_errors = reader.readNextShort();
		s_minor_rev_level = reader.readNextShort();
		s_lastcheck = reader.readNextInt();
		s_checkinterval = reader.readNextInt();
		s_creator_os = reader.readNextInt();
		s_rev_level = reader.readNextInt();
		s_def_resuid = reader.readNextShort();
		s_def_resgid = reader.readNextShort();
		s_first_ino = reader.readNextInt();
		s_inode_size = reader.readNextShort();
		s_block_group_nr = reader.readNextShort();
		s_feature_compat = reader.readNextInt();
		s_feature_incompat = reader.readNextInt();
		s_feature_ro_compat = reader.readNextInt();
		s_uuid = reader.readNextByteArray(16);
		s_volume_name = reader.readNextByteArray(16);
		s_last_mounted = reader.readNextByteArray(64);
		s_algorithm_usage_bitmap = reader.readNextInt();
		s_prealloc_blocks = reader.readNextByte();
		s_prealloc_dir_blocks = reader.readNextByte();
		s_reserved_gdt_blocks = reader.readNextShort();
		s_journal_uuid = reader.readNextByteArray(16);
		s_journal_inum = reader.readNextInt();
		s_journal_dev = reader.readNextInt();
		s_last_orphan = reader.readNextInt();
		s_hash_seed = reader.readNextIntArray(4);
		s_def_hash_version = reader.readNextByte();
		s_jnl_backup_type = reader.readNextByte();
		s_desc_size = reader.readNextShort();
		s_default_mount_opts = reader.readNextInt();
		s_first_meta_bg = reader.readNextInt();
		s_mkfs_time = reader.readNextInt();
		s_jnl_blocks = reader.readNextIntArray(17);
		s_blocks_count_hi = reader.readNextInt();
		s_r_blocks_count_hi = reader.readNextInt();
		s_free_blocks_count_hi = reader.readNextInt();
		s_min_extra_isize = reader.readNextShort();
		s_want_extra_isize = reader.readNextShort();
		s_flags = reader.readNextInt();
		s_raid_stride = reader.readNextShort();
		s_mmp_interval = reader.readNextShort();
		s_mmp_block = reader.readNextLong();
		s_raid_stripe_width = reader.readNextInt();
		s_log_groups_per_flex = reader.readNextByte();
		s_checksum_type = reader.readNextByte();
		s_reserved_pad = reader.readNextShort();
		s_kbytes_written = reader.readNextLong();
		s_snapshot_inum = reader.readNextInt();
		s_snapshot_id = reader.readNextInt();
		s_snapshot_r_blocks_count = reader.readNextLong();
		s_snapshot_list = reader.readNextInt();
		s_error_count = reader.readNextInt();
		s_first_error_time = reader.readNextInt();
		s_first_error_ino = reader.readNextInt();
		s_first_error_block = reader.readNextLong();
		s_first_error_func = reader.readNextByteArray(32);
		s_first_error_line = reader.readNextInt();
		s_last_error_time = reader.readNextInt();
		s_last_error_ino = reader.readNextInt();
		s_last_error_line = reader.readNextInt();
		s_last_error_block = reader.readNextLong();
		s_last_error_func = reader.readNextByteArray(32);
		s_mount_opts = reader.readNextByteArray(64);
		s_usr_quora_inum = reader.readNextInt();
		s_grp_quota_inum = reader.readNextInt();
		s_overhead_blocks = reader.readNextInt();
		s_backup_blocks = reader.readNextIntArray(2);
		s_encrypt_algos = reader.readNextByteArray(4);
		s_encrypt_pw_salt = reader.readNextByteArray(16);
		s_lpf_ino = reader.readNextInt();
		s_prj_quota_inum = reader.readNextInt();
		s_checksum_seed = reader.readNextInt();
		s_reserved = reader.readNextIntArray(98);
		s_checksum = reader.readNextInt();
	}

	public int getS_inodes_count() {
		return s_inodes_count;
	}

	public int getS_blocks_count_lo() {
		return s_blocks_count_lo;
	}

	public int getS_r_blocks_count_lo() {
		return s_r_blocks_count_lo;
	}

	public int getS_free_blocks_count_lo() {
		return s_free_blocks_count_lo;
	}

	public int getS_free_inodes_count() {
		return s_free_inodes_count;
	}

	public int getS_first_data_block() {
		return s_first_data_block;
	}

	public int getS_log_block_size() {
		return s_log_block_size;
	}

	public int getS_log_cluster_size() {
		return s_log_cluster_size;
	}

	public int getS_blocks_per_group() {
		return s_blocks_per_group;
	}

	public int getS_clusters_per_group() {
		return s_clusters_per_group;
	}

	public int getS_inodes_per_group() {
		return s_inodes_per_group;
	}

	public int getS_mtime() {
		return s_mtime;
	}

	public int getS_wtime() {
		return s_wtime;
	}

	public short getS_mnt_count() {
		return s_mnt_count;
	}

	public short getS_max_mnt_count() {
		return s_max_mnt_count;
	}

	public short getS_magic() {
		return s_magic;
	}

	public short getS_state() {
		return s_state;
	}

	public short getS_errors() {
		return s_errors;
	}

	public short getS_minor_rev_level() {
		return s_minor_rev_level;
	}

	public int getS_lastcheck() {
		return s_lastcheck;
	}

	public int getS_checkinterval() {
		return s_checkinterval;
	}

	public int getS_creator_os() {
		return s_creator_os;
	}

	public int getS_rev_level() {
		return s_rev_level;
	}

	public short getS_def_resuid() {
		return s_def_resuid;
	}

	public short getS_def_resgid() {
		return s_def_resgid;
	}

	public int getS_first_ino() {
		return s_first_ino;
	}

	public short getS_inode_size() {
		return s_inode_size;
	}

	public short getS_block_group_nr() {
		return s_block_group_nr;
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

	public byte[] getS_volume_name() {
		return s_volume_name;
	}

	public String getVolumeName() {
		int i = 0;
		while (i < s_volume_name.length && s_volume_name[i] != '\0') {
			i++;
		}
		return new String(s_volume_name, 0, i, Ext4FileSystem.EXT4_DEFAULT_CHARSET);
	}

	public byte[] getS_last_mounted() {
		return s_last_mounted;
	}

	public int getS_algorithm_usage_bitmap() {
		return s_algorithm_usage_bitmap;
	}

	public byte getS_prealloc_blocks() {
		return s_prealloc_blocks;
	}

	public byte getS_prealloc_dir_blocks() {
		return s_prealloc_dir_blocks;
	}

	public short getS_reserved_gdt_blocks() {
		return s_reserved_gdt_blocks;
	}

	public byte[] getS_journal_uuid() {
		return s_journal_uuid;
	}

	public int getS_journal_inum() {
		return s_journal_inum;
	}

	public int getS_journal_dev() {
		return s_journal_dev;
	}

	public int getS_last_orphan() {
		return s_last_orphan;
	}

	public int[] getS_hash_seed() {
		return s_hash_seed;
	}

	public byte getS_def_hash_version() {
		return s_def_hash_version;
	}

	public byte getS_jnl_backup_type() {
		return s_jnl_backup_type;
	}

	public short getS_desc_size() {
		return s_desc_size;
	}

	public int getS_default_mount_opts() {
		return s_default_mount_opts;
	}

	public int getS_first_meta_bg() {
		return s_first_meta_bg;
	}

	public int getS_mkfs_time() {
		return s_mkfs_time;
	}

	public int[] getS_jnl_blocks() {
		return s_jnl_blocks;
	}

	public int getS_blocks_count_hi() {
		return s_blocks_count_hi;
	}

	public int getS_r_blocks_count_hi() {
		return s_r_blocks_count_hi;
	}

	public int getS_free_blocks_count_hi() {
		return s_free_blocks_count_hi;
	}

	public short getS_min_extra_isize() {
		return s_min_extra_isize;
	}

	public short getS_want_extra_isize() {
		return s_want_extra_isize;
	}

	public int getS_flags() {
		return s_flags;
	}

	public short getS_raid_stride() {
		return s_raid_stride;
	}

	public short getS_mmp_interval() {
		return s_mmp_interval;
	}

	public long getS_mmp_block() {
		return s_mmp_block;
	}

	public int getS_raid_stripe_width() {
		return s_raid_stripe_width;
	}

	public byte getS_log_groups_per_flex() {
		return s_log_groups_per_flex;
	}

	public byte getS_checksum_type() {
		return s_checksum_type;
	}

	public short getS_reserved_pad() {
		return s_reserved_pad;
	}

	public long getS_kbytes_written() {
		return s_kbytes_written;
	}

	public int getS_snapshot_inum() {
		return s_snapshot_inum;
	}

	public int getS_snapshot_id() {
		return s_snapshot_id;
	}

	public long getS_snapshot_r_blocks_count() {
		return s_snapshot_r_blocks_count;
	}

	public int getS_snapshot_list() {
		return s_snapshot_list;
	}

	public int getS_error_count() {
		return s_error_count;
	}

	public int getS_first_error_time() {
		return s_first_error_time;
	}

	public int getS_first_error_ino() {
		return s_first_error_ino;
	}

	public long getS_first_error_block() {
		return s_first_error_block;
	}

	public byte[] getS_first_error_func() {
		return s_first_error_func;
	}

	public int getS_first_error_line() {
		return s_first_error_line;
	}

	public int getS_last_error_time() {
		return s_last_error_time;
	}

	public int getS_Last_error_ino() {
		return s_last_error_ino;
	}

	public int getS_last_error_line() {
		return s_last_error_line;
	}

	public long getS_last_error_block() {
		return s_last_error_block;
	}

	public byte[] getS_last_error_func() {
		return s_last_error_func;
	}

	public byte[] getS_mount_opts() {
		return s_mount_opts;
	}

	public int getS_usr_quora_inum() {
		return s_usr_quora_inum;
	}

	public int getS_grp_quota_inum() {
		return s_grp_quota_inum;
	}

	public int getS_overhead_blocks() {
		return s_overhead_blocks;
	}

	public int[] getS_backup_blocks() {
		return s_backup_blocks;
	}

	public byte[] getS_encrypt_algos() {
		return s_encrypt_algos;
	}

	public byte[] getS_encrypt_pw_salt() {
		return s_encrypt_pw_salt;
	}

	public int getS_lpf_ino() {
		return s_lpf_ino;
	}

	public int getS_prj_quota_inum() {
		return s_prj_quota_inum;
	}

	public int getS_checksum_seed() {
		return s_checksum_seed;
	}

	public int[] getS_reserved() {
		return s_reserved;
	}

	public int getS_checksum() {
		return s_checksum;
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("ext4_super_block", 0);
		structure.add(DWORD, "s_inodes_count", null);
		structure.add(DWORD, "s_blocks_count_lo", null);
		structure.add(DWORD, "s_r_blocks_count_lo", null);
		structure.add(DWORD, "s_free_blocks_count_lo", null);
		structure.add(DWORD, "s_free_inodes_count", null);
		structure.add(DWORD, "s_first_data_block", null);
		structure.add(DWORD, "s_log_block_size", null);
		structure.add(DWORD, "s_log_cluster_size", null);
		structure.add(DWORD, "s_blocks_per_group", null);
		structure.add(DWORD, "s_clusters_per_group", null);
		structure.add(DWORD, "s_inodes_per_group", null);
		structure.add(DWORD, "s_mtime", null);
		structure.add(DWORD, "s_wtime", null);
		structure.add(WORD, "s_mnt_count", null);
		structure.add(WORD, "s_max_mnt_count", null);
		structure.add(WORD, "s_magic", null);
		structure.add(WORD, "s_state", null);
		structure.add(WORD, "s_errors", null);
		structure.add(WORD, "s_minor_rev_level", null);
		structure.add(DWORD, "s_lastcheck", null);
		structure.add(DWORD, "s_checkinterval", null);
		structure.add(DWORD, "s_creator_os", null);
		structure.add(DWORD, "s_rev_level", null);
		structure.add(WORD, "s_def_resuid", null);
		structure.add(WORD, "s_def_resgid", null);
		structure.add(DWORD, "s_first_ino", null);
		structure.add(WORD, "s_inode_size", null);
		structure.add(WORD, "s_block_group_nr", null);
		structure.add(DWORD, "s_feature_compat", null);
		structure.add(DWORD, "s_feature_incompat", null);
		structure.add(DWORD, "s_feature_ro_compat", null);
		structure.add(new ArrayDataType(BYTE, 16, BYTE.getLength()), "s_uuid", null);
		structure.add(new ArrayDataType(BYTE, 16, BYTE.getLength()), "s_volume_name", null);
		structure.add(new ArrayDataType(BYTE, 64, BYTE.getLength()), "s_last_mounted", null);
		structure.add(DWORD, "s_algorithm_usage_bitmap", null);
		structure.add(BYTE, "s_prealloc_blocks", null);
		structure.add(BYTE, "s_prealloc_dir_blocks", null);
		structure.add(WORD, "s_reserved_gdt_blocks", null);
		structure.add(new ArrayDataType(BYTE, 16, BYTE.getLength()), "s_journal_uuid", null);
		structure.add(DWORD, "s_journal_inum", null);
		structure.add(DWORD, "s_journal_dev", null);
		structure.add(DWORD, "s_last_orphan", null);
		structure.add(new ArrayDataType(DWORD, 4, DWORD.getLength()), "s_hash_seed", null);
		structure.add(BYTE, "s_def_hash_version", null);
		structure.add(BYTE, "s_jnl_backup_type", null);
		structure.add(WORD, "s_desc_size", null);
		structure.add(DWORD, "s_default_mount_opts", null);
		structure.add(DWORD, "s_first_meta_bg", null);
		structure.add(DWORD, "s_mkfs_time", null);
		structure.add(new ArrayDataType(DWORD, 17, DWORD.getLength()), "s_jnl_blocks", null);
		structure.add(DWORD, "s_blocks_count_hi", null);
		structure.add(DWORD, "s_r_blocks_count_hi", null);
		structure.add(DWORD, "s_free_blocks_count_hi", null);
		structure.add(WORD, "s_min_extra_isize", null);
		structure.add(WORD, "s_want_extra_isize", null);
		structure.add(DWORD, "s_flags", null);
		structure.add(WORD, "s_raid_stride", null);
		structure.add(WORD, "s_mmp_interval", null);
		structure.add(QWORD, "s_mmp_block", null);
		structure.add(DWORD, "s_raid_stripe_width", null);
		structure.add(BYTE, "s_log_groups_per_flex", null);
		structure.add(BYTE, "s_checksum_type", null);
		structure.add(WORD, "s_reserved_pad", null);
		structure.add(QWORD, "s_kbytes_written", null);
		structure.add(DWORD, "s_snapshot_inum", null);
		structure.add(DWORD, "s_snapshot_id", null);
		structure.add(QWORD, "s_snapshot_r_blocks_count", null);
		structure.add(DWORD, "s_snapshot_list", null);
		structure.add(DWORD, "s_error_count", null);
		structure.add(DWORD, "s_first_error_time", null);
		structure.add(DWORD, "s_first_error_ino", null);
		structure.add(QWORD, "s_first_error_block", null);
		structure.add(new ArrayDataType(BYTE, 32, BYTE.getLength()), "s_first_error_func", null);
		structure.add(DWORD, "s_first_error_line", null);
		structure.add(DWORD, "s_last_error_time", null);
		structure.add(DWORD, "s_last_error_ino", null);
		structure.add(DWORD, "s_last_error_line", null);
		structure.add(QWORD, "s_last_error_block", null);
		structure.add(new ArrayDataType(BYTE, 32, BYTE.getLength()), "s_last_error_func", null);
		structure.add(new ArrayDataType(BYTE, 64, BYTE.getLength()), "s_mount_opts", null);
		structure.add(DWORD, "s_usr_quora_inum", null);
		structure.add(DWORD, "s_grp_quota_inum", null);
		structure.add(DWORD, "s_overhead_blocks", null);
		structure.add(new ArrayDataType(DWORD, 2, DWORD.getLength()), "s_backup_blocks", null);
		structure.add(new ArrayDataType(BYTE, 4, BYTE.getLength()), "s_encrypt_algos", null);
		structure.add(new ArrayDataType(BYTE, 16, BYTE.getLength()), "s_encrypt_pw_salt", null);
		structure.add(DWORD, "s_lpf_ino", null);
		structure.add(DWORD, "s_prj_quota_inum", null);
		structure.add(DWORD, "s_checksum_seed", null);
		structure.add(new ArrayDataType(DWORD, 98, DWORD.getLength()), "s_reserved", null);
		structure.add(DWORD, "s_checksum", null);
		return structure;
	}
	
}
