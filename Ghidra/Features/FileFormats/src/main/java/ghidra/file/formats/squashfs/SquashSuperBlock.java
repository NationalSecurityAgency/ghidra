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

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class SquashSuperBlock {

	/**
	 * ===== 32 BIT INTEGER VALUES =====
	 */

	// The magic for a Squash file. "HSQS" for little endian, "SQSH" for big endian
	private final int magic;

	// The number of inodes in the archive
	private final long inodeCount;

	// Unix timestamp of the last time the archive was modified (not counting leap seconds)
	private final long modTime;

	// The size of a data block in bytes (must be a power of 2 between 4KB and 1 MiB)
	private final long blockSize;

	// The number of entries in the fragment table
	private final long totalFragments;

	/**
	 * ===== 16 BIT SHORT VALUES =====
	 */

	// The type of compression used
	private final int compressionType;

	// This should equal log2(blockSize). If that's not the case, the archive is considered corrupt
	private final int blockLog;

	// Flags with additional information about the archive
	private final int flags;

	// The number of entries in the ID lookup table
	private final int totalIDs;

	// The major SquashFS version (should always be 4)
	private final int majorVersion;

	// The minor SquashFS version (should always be 0)
	private final int minorVersion;

	/**
	 * ===== 64 BIT LONG VALUES =====
	 */

	// A reference to the inode of the root directory
	// The upper 48 bits are the location where the metadata block resides
	// The lower 16 bits are the offset into the uncompressed metadata block where the inode starts
	private final long rootInode;

	// The number of bytes used by the archive. This may be less than the file size due to the 
	// total file size needing to be padded to be a multiple of the block size
	private final long bytesUsed;

	// The byte offset to the start of the ID table
	private final long idTableStart;

	// The byte offset to the start of the XATTR ID table
	private final long xattrIdTableStart;

	// The byte offset to the start of the inode table
	private final long inodeTableStart;

	// The byte offset to the start of the directory table
	private final long directoryTableStart;

	// The byte offset to the start of the fragment table
	private final long fragmentTableStart;

	// The byte offset to the start of the export table
	private final long exportTableStart;

	/**
	 * ===== FLAGS BREAKDOWN =====
	 * NOTE: Descriptions are for if the flag is set
	 * 0x0001 - inodes are not compressed (NOTE: UID/GIDs also share this setting)
	 * 0x0002 - Data blocks are not compressed
	 * 0x0004 - Not used in SquashFS version 4+. This should never be set
	 * 0x0008 - Fragments are not compressed
	 * 0x0010 - Files are not fragmented and will be padded to reach a full block size
	 * 0x0020 - If last block size < block size, it will be stored as a fragment
	 * 0x0040 - Identical files are only stored once
	 * 0x0080 - The export table is populated, allowing for exporting via NFS
	 * 0x0100 - The Xattrs are stored uncompressed
	 * 0x0200 - There are no Xattrs in the archive
	 * 0x0400 - The compression algorithms section is present (only for certain algorithms)
	 * 0x0800 - The ID table is uncompressed
	 */

	/**
	 * Represents the SuperBlock (archive processing information) within the SquashFS archive
	 * @param reader A binary reader for the entire SquashFS archive
	 * @throws IOException Any read operation failure
	 */
	SquashSuperBlock(BinaryReader reader) throws IOException {

		// Fetch the 32 bit integer fields
		magic = reader.readNextUnsignedIntExact();
		inodeCount = reader.readNextUnsignedInt();
		modTime = reader.readNextUnsignedInt();
		blockSize = reader.readNextUnsignedInt();
		totalFragments = reader.readNextUnsignedInt();

		// Fetch the 16 bit short fields
		compressionType = reader.readNextUnsignedShort();
		blockLog = reader.readNextUnsignedShort();
		flags = reader.readNextUnsignedShort();
		totalIDs = reader.readNextUnsignedShort();
		majorVersion = reader.readNextUnsignedShort();
		minorVersion = reader.readNextUnsignedShort();

		// Fetch the 64 bit long fields
		rootInode = reader.readNextLong();
		bytesUsed = reader.readNextLong();
		idTableStart = reader.readNextLong();
		xattrIdTableStart = reader.readNextLong();
		inodeTableStart = reader.readNextLong();
		directoryTableStart = reader.readNextLong();
		fragmentTableStart = reader.readNextLong();
		exportTableStart = reader.readNextLong();

		// Check that the SuperBlock values are what is expected by this FileSystem
		checkCompatibility();
	}

	public long getMagicBytes() {
		return magic;
	}

	public long getInodeCount() {
		return inodeCount;
	}

	public long getModTime() {
		return modTime;
	}

	public long getBlockSize() {
		return blockSize;
	}

	public long getTotalFragments() {
		return totalFragments;
	}

	public int getCompressionType() {
		return compressionType;
	}

	public int getBlockLog() {
		return blockLog;
	}

	public int getRawFlags() {
		return flags;
	}

	public int getTotalIDs() {
		return totalIDs;
	}

	public int getMajorVersion() {
		return majorVersion;
	}

	public int getMinorVersion() {
		return minorVersion;
	}

	public long getRootInode() {
		return rootInode;
	}

	public long getRootInodeBlockLocation() {
		return rootInode >> 16;
	}

	public long getRootInodeOffset() {
		return rootInode & 0xFFFF;
	}

	public long getBytesUsed() {
		return bytesUsed;
	}

	public long getIdTableStart() {
		return idTableStart;
	}

	public long getXattrIdTableStart() {
		return xattrIdTableStart;
	}

	public long getInodeTableStart() {
		return inodeTableStart;
	}

	public long getDirectoryTableStart() {
		return directoryTableStart;
	}

	public long getFragmentTableStart() {
		return fragmentTableStart;
	}

	public long getExportTableStart() {
		return exportTableStart;
	}

	public boolean isInodesUncompressed() {
		return (flags & SquashConstants.UNCOMPRESSED_INODES) != 0;
	}

	public boolean isDataUncompressed() {
		return (flags & SquashConstants.UNCOMPRESSED_DATA_BLOCKS) != 0;
	}

	public boolean isUsedFlagSet() {
		return (flags & SquashConstants.UNUSED_FLAG) != 0;
	}

	public boolean isFragmentsUncompressed() {
		return (flags & SquashConstants.UNCOMPRESSED_FRAGMENTS) != 0;
	}

	public boolean isFragmentsUnused() {
		return (flags & SquashConstants.NO_FRAGMENTS) != 0;
	}

	public boolean isAlwaysFragment() {
		return (flags & SquashConstants.ALWAYS_FRAGMENT) != 0;
	}

	public boolean allowDuplicates() {
		return (flags & SquashConstants.NO_DUPLICATE_DATE) != 0;
	}

	public boolean isExportable() {
		return (flags & SquashConstants.EXPORT_TABLE_EXISTS) != 0;
	}

	public boolean isXattrsUncompressed() {
		return (flags & SquashConstants.UNCOMPRESSED_XATTRS) != 0;
	}

	public boolean hasXattrs() {
		return (flags & SquashConstants.NO_XATTRS) != 0;
	}

	public boolean isCompressionOptionsPresent() {
		return (flags & SquashConstants.COMPRESSION_OPTIONS_EXIST) != 0;
	}

	public boolean isIDsUncompressed() {
		return (flags & SquashConstants.UNCOMPRESSED_IDS) != 0;
	}

	public String getVersionString() {
		return majorVersion + "." + minorVersion;
	}

	/**
	 * Validate the SuperBlock against expected values and warn the user of any possible issues
	 */
	public void checkCompatibility() {
		// Verify the SquashFS version and warn the user if it isn't 4.0
		if ((this.majorVersion != 4) || (this.minorVersion != 0)) {
			Msg.warn(this, "SquashFS archive is version " + majorVersion + "." + minorVersion +
				" but Ghidra has only been tested with version 4.0");
		}

		// Let the user know if the Xattr table is missing
		if ((xattrIdTableStart == SquashConstants.SECTION_OMITTED)) {
			Msg.info(this, "In SquashFS archive, the optional Xattr table is missing");
		}

		// Let the user know if the fragment table is missing
		if ((fragmentTableStart == SquashConstants.SECTION_OMITTED)) {
			Msg.info(this, "In SquashFS archive, the optional fragment table is missing");
		}

		// Let the user know if the export table is missing
		if ((exportTableStart == SquashConstants.SECTION_OMITTED)) {
			Msg.info(this, "In SquashFS archive, the optional export table is missing");
		}

		// Check if the unused flag is set and warn the user if it is
		if (isUsedFlagSet() && (majorVersion >= 4)) {
			Msg.warn(this,
				"In SquashFS archive super block, the unused flag is set when it should " +
					"be cleared. Per standard, the archive is invalid. Continue with caution!");
		}

		// Check if blockLog is correct and warn the user if not
		if (1 << blockLog != blockSize) {
			Msg.warn(this,
				"In SquashFS archive super block, the blocksize does not match the blockLog value." +
					" Per standard, the archive is invalid. Continue with caution!");
		}

		// Check if the flags for compressed inodes and compressed IDs match and warn the user if not
		if ((isInodesUncompressed() != isIDsUncompressed()) && (majorVersion >= 4)) {
			Msg.warn(this,
				"In SquashFS archive super block, the flags for whether inodes and IDs" +
					"are compressed should match. This is to maintain backwards compantability, " +
					"but they differ in your archive. Continue with caution!");
		}
	}

	public String getCompressionTypeString() {
		switch (compressionType) {
			case SquashConstants.COMPRESSION_TYPE_GZIP:
				return "gzip";
			case SquashConstants.COMPRESSION_TYPE_LZMA:
				return "lzma";
			case SquashConstants.COMPRESSION_TYPE_LZO:
				return "lzo";
			case SquashConstants.COMPRESSION_TYPE_XZ:
				return "xz";
			case SquashConstants.COMPRESSION_TYPE_LZ4:
				return "lz4-block";
			case SquashConstants.COMPRESSION_TYPE_ZSTD:
				return "zstd";
			default:
				return "Unknown";
		}
	}
}
