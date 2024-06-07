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

public class SquashExtendedFileInode extends SquashBasicFileInode {

	// The number of bytes saved by omitting zero bytes
	private long sparseCount;

	// The number of hard links to this inode
	private long linkCount;

	// An index into the Xattr table or 0xFFFFFFFF if no this inode has no xattrs
	private long xattrIndex;

	/**
	 * Represents a SquashFS extended file inode
	 * @param reader A binary reader with pointer index at the start of the inode data
	 * @param superBlock The SuperBlock for the current archive
	 * @throws IOException Any read operation failure
	 */
	public SquashExtendedFileInode(BinaryReader reader, SquashSuperBlock superBlock)
			throws IOException {

		// Assign common inode header values
		super(reader, superBlock, true);

		// Assign extended file specific values
		startBlockOffset = reader.readNextLong();
		fileSize = reader.readNextLong();
		sparseCount = reader.readNextLong();
		linkCount = reader.readNextUnsignedInt();

		// If there are no fragments, skip the next two values
		if (reader.peekNextInt() == -1) {
			fragmentIndex = -1;
			blockOffset = -1;

			// Advance the reader position
			reader.setPointerIndex(reader.getPointerIndex() + (BinaryReader.SIZEOF_INT * 2));
		}
		else {
			fragmentIndex = reader.readNextUnsignedIntExact();
			blockOffset = reader.readNextUnsignedIntExact();
		}

		xattrIndex = reader.readNextUnsignedInt();

		// Calculate derived variables
		setVars(reader, superBlock);
	}

	public long getSparseCount() {
		return sparseCount;
	}

	public long getLinkCount() {
		return linkCount;
	}

	public long getXattrIndex() {
		return xattrIndex;
	}
}
