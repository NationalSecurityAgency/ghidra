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

public class SquashBasicDirectoryInode extends SquashInode {

	// Offset into the directory table where the metadata block for this inode starts
	protected long blockIndex;

	// The number of hard links to this directory
	protected long hardLinkCount;

	// The total uncompressed size of this directory listing
	// Basic is 16 bits, extended is 32 bits (unsigned)
	// NOTE: This value is 3 bytes greater than the actual listing as Linux creates "." and ".." directories
	protected long uncompressedFileSize;

	// Offset into the directory table metadata block where this directory listing starts
	protected int blockOffset;

	// The inode number of the parent of this directory (for root directory, this should be 0)
	protected int parentInodeNumber;

	// Whether or not the parent directory is root
	protected boolean parentIsRoot = false;

	/**
	 * Represents a SquashFS basic directory inode
	 * @param reader A binary reader with pointer index at the start of the inode data
	 * @param superBlock The SuperBlock for the current archive
	 * @param isExtended True if the constructor is being called by a subclass
	 * @throws IOException Any read operation failure
	 */
	public SquashBasicDirectoryInode(BinaryReader reader, SquashSuperBlock superBlock,
			boolean isExtended) throws IOException {

		// Assign common inode header values
		super(reader, superBlock);

		// If the class if being extended, handle the directory-specific values in that constructor
		if (isExtended) {
			return;
		}

		// Assign basic directory specific values
		blockIndex = reader.readNextUnsignedInt();
		hardLinkCount = reader.readNextUnsignedInt();
		uncompressedFileSize = reader.readNextUnsignedShort();
		blockOffset = reader.readNextUnsignedShort();
		parentInodeNumber = reader.readNextUnsignedIntExact();

		// Determine if the parent of the current inode is root
		parentIsRoot = parentInodeNumber == superBlock.getInodeCount() + 1;

	}

	public int getParentInodeNumber() {
		return parentInodeNumber;
	}

	public boolean isParentRoot() {
		return parentIsRoot;
	}

	public long getIndex() {
		return blockIndex;
	}

	public long getHardLinkCount() {
		return hardLinkCount;
	}

	public int getOffset() {
		return blockOffset;
	}

	public long getUncompressedSize() {
		return uncompressedFileSize;
	}
}
