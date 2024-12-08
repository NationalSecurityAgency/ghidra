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

public class SquashInode {

	// The type of inode as an integer
	private final short inodeType;

	// Unix file permissions bitmask
	private final short permissions;

	// Index into the ID table where the user ID of the owner resides
	private final int userID;

	// Index into the ID table where the group ID of the owner resides
	private final int groupID;

	// Unix timestamp of the last time the inode was modified (not counting leap seconds)
	private final long modTime;

	// A unique number for this inode. Must be at least 1 and less than the total number of inodes
	private final int inodeNumber;

	// The parent of this inode
	private SquashInode parent = null;

	// The directory table entry that refers to this inode
	private SquashDirectoryTableEntry directoryTableEntry;

	/**
	 * Represents a generic SquashFS inode
	 * @param reader A binary reader with pointer index at the start of the inode data
	 * @param superBlock The SuperBlock for the current archive
	 * @throws IOException Any read operation failure
	 */
	public SquashInode(BinaryReader reader, SquashSuperBlock superBlock) throws IOException {

		// Assign common inode header values
		inodeType = reader.readNextShort();
		permissions = reader.readNextShort();
		userID = reader.readNextUnsignedShort();
		groupID = reader.readNextUnsignedShort();
		modTime = reader.readNextUnsignedInt();
		inodeNumber = reader.readNextUnsignedIntExact();
	}

	public short getPermissions() {
		return permissions;
	}

	public short getType() {
		return inodeType;
	}

	public int getUserID() {
		return userID;
	}

	public int getGroupID() {
		return groupID;
	}

	public long getModTime() {
		return modTime;
	}

	public int getNumber() {
		return inodeNumber;
	}

	void setParent(SquashInode parentInode) {
		parent = parentInode;
	}

	public SquashBasicDirectoryInode getParent() {
		if (!parent.isDir()) {
			return null;
		}
		return (SquashBasicDirectoryInode) parent;
	}

	void setDirectoryTableEntry(SquashDirectoryTableEntry entry) {
		directoryTableEntry = entry;
	}

	public SquashDirectoryTableEntry getDirectoryTableEntry() {
		return directoryTableEntry;
	}

	public boolean isDir() {
		return inodeType == SquashConstants.INODE_TYPE_BASIC_DIRECTORY ||
			inodeType == SquashConstants.INODE_TYPE_EXTENDED_DIRECTORY;
	}

	public boolean isFile() {
		return inodeType == SquashConstants.INODE_TYPE_BASIC_FILE ||
			inodeType == SquashConstants.INODE_TYPE_EXTENDED_FILE;
	}

	public boolean isSymLink() {
		return inodeType == SquashConstants.INODE_TYPE_BASIC_SYMLINK ||
			inodeType == SquashConstants.INODE_TYPE_EXTENDED_SYMLINK;
	}
}
