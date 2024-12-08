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

public class SquashDirectoryTableEntry {

	// Offset into the uncompressed directory table where this entry is
	private final int addressOffset;

	// Added to the base inode number to get the sub-entry inode number (note: signed short)
	private final short inodeNumberOffset;

	// Stores the basic inode type (i.e. if it's an "extended file" inode, it will be a "basic file" here)
	private final short inodeType;

	// The number of bytes that will represent the name of this sub-entry
	private final short nameSize;

	// The result of the addition of the base inode and the offset
	private final int inodeNumber;

	// Upon creation, this is just the name of this sub-entry, but will be expanded to the full path
	private String path;

	/**
	 * Represents an entry in the directory table
	 * @param reader A binary reader with pointer index at the start of the entry data
	 * @param superBlock The SuperBlock for the current archive
	 * @param baseInode The base inode number that is used to calculate the current number
	 * @throws IOException Any read operation failure
	 */
	public SquashDirectoryTableEntry(BinaryReader reader, SquashSuperBlock superBlock,
			long baseInode) throws IOException {

		addressOffset = reader.readNextUnsignedShort();
		inodeNumberOffset = reader.readNextShort(); // NOTE: Signed
		inodeType = reader.readNextShort();
		nameSize = reader.readNextShort();

		// The stored filename doesn't include the terminating null byte
		// Note: Though technically 16 bits, Linux caps name size at 256 chars
		path = reader.readNextAsciiString(nameSize + 1);

		// Find the inode number using the base in the table entry header and the offset
		inodeNumber = (int) (baseInode + inodeNumberOffset);

	}

	public int getAddressOffset() {
		return addressOffset;
	}

	public short getInodeType() {
		return inodeType;
	}

	// Extract the filename from the path
	public String getFileName() {
		int slashIndex = path.lastIndexOf('/');

		// If the path is still just the name of the file
		if (slashIndex == -1) {
			return path;
		}

		return path.substring(slashIndex);

	}

	public int getInodeNumber() {
		return inodeNumber;
	}

	public String getPath() {
		return path;
	}
}
