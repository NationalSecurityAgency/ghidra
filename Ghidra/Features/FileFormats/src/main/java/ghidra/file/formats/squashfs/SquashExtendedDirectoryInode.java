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

public class SquashExtendedDirectoryInode extends SquashBasicDirectoryInode {

	// The number of directory indexes that follow the main inode structure
	private int indexCount;

	// An index into the Xattr table or 0xFFFFFFFF if no this inode has no xattrs
	private long xattrIndex;

	/**
	 * Represents a SquashFS extended directory inode
	 * @param reader A binary reader with pointer index at the start of the inode data
	 * @param superBlock The SuperBlock for the current archive
	 * @throws IOException Any read operation failure
	 */
	public SquashExtendedDirectoryInode(BinaryReader reader, SquashSuperBlock superBlock)
			throws IOException {

		// Assign common inode header values
		super(reader, superBlock, true);

		// Assign extended directory specific values
		hardLinkCount = reader.readNextUnsignedInt();
		uncompressedFileSize = reader.readNextUnsignedInt();
		blockIndex = reader.readNextUnsignedInt();
		parentInodeNumber = reader.readNextUnsignedIntExact();
		indexCount = reader.readNextUnsignedShort();
		blockOffset = reader.readNextUnsignedShort();
		xattrIndex = reader.readNextUnsignedInt();

		// Skip all directory indexes following the inode
		for (int i = 0; i < indexCount; i++) {
			skipDirectoryListing(reader);
		}

		// Determine if the parent of the current inode is root
		parentIsRoot = parentInodeNumber == superBlock.getInodeCount() + 1;

	}

	/**
	 * Skip the current directory listing as this implementation does not utilize them
	 * @param reader A binary reader with pointer index at the start of the directory listing
	 * @throws IOException Any read operation failure
	 */
	private void skipDirectoryListing(BinaryReader reader) throws IOException {
		long index = reader.readNextUnsignedInt();
		long start = reader.readNextUnsignedInt();
		int nameSize = reader.readNextInt();
		String name = reader.readNextAsciiString(nameSize + 1);
	}

	long getXattrIndex() {
		return xattrIndex;
	}
}
