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

public class SquashBasicFileInode extends SquashInode {

	// Offset into the archive where the first data block resides
	// Basic is 32 bits, extended is 64 bits
	protected long startBlockOffset;

	// The index into the fragment table where the tail end of this file resides
	// All bits are set if there is no fragment
	protected int fragmentIndex;

	// The offset within the uncompressed fragment block where the tail end of the file resides
	protected int blockOffset;

	// The total uncompressed size of this file
	// Basic is 32 bits, extended is 64 bits
	protected long fileSize;

	// An array containing the number of bytes each block in the archive is
	protected int[] blockSizes;

	// The size of the tail end of the file
	protected int tailEndSize = 0;

	// The total number of blocks comprising the file
	protected int numberOfBlocks = 0;

	/**
	 * Represents a SquashFS basic file inode
	 * @param reader A binary reader with pointer index at the start of the inode data
	 * @param superBlock The SuperBlock for the current archive
	 * @param isExtended True if the constructor is being called by a subclass
	 * @throws IOException Any read operation failure
	 */
	public SquashBasicFileInode(BinaryReader reader, SquashSuperBlock superBlock,
			boolean isExtended) throws IOException {

		// Assign common inode header values
		super(reader, superBlock);

		// If the class if being extended, handle the file-specific values in that constructor
		if (isExtended) {
			return;
		}

		// Assign basic file specific values
		startBlockOffset = reader.readNextUnsignedInt();

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

		fileSize = reader.readNextUnsignedInt();

		setVars(reader, superBlock);

	}

	/**
	 * Calculate the derived variables for this file
	 * @param reader A binary reader with pointer index at the start of the inode data
	 * @param superBlock The superblock for the current archive
	 * @throws IOException Any read operation failure
	 */
	protected void setVars(BinaryReader reader, SquashSuperBlock superBlock) throws IOException {

		// If the current inode uses fragments, the number of blocks is calculated differently
		if (fragmentIndex == SquashConstants.INODE_NO_FRAGMENTS) {
			numberOfBlocks =
				(int) ((fileSize + superBlock.getBlockSize() - 1) / superBlock.getBlockSize());
		}
		else {
			numberOfBlocks = (int) (fileSize / superBlock.getBlockSize());
			tailEndSize = (int) (fileSize % superBlock.getBlockSize());
		}

		// Fetch and store the block sizes for the file
		blockSizes = reader.readNextIntArray(numberOfBlocks);
	}

	public long getStartBlockOffset() {
		return startBlockOffset;
	}

	public int getFragmentIndex() {
		return fragmentIndex;
	}

	public int getBlockOffset() {
		return blockOffset;
	}

	public long getFileSize() {
		return fileSize;
	}

	public int getTailEndSize() {
		return tailEndSize;
	}

	public int getNumberOfBlocks() {
		return numberOfBlocks;
	}

	public int[] getBlockSizes() {
		return blockSizes;
	}

	public long getCompressedFileSize() {
		long compressedSize = 0;

		for (int blockHeader : blockSizes) {
			int size = blockHeader & ~SquashConstants.DATABLOCK_COMPRESSED_MASK;
			compressedSize += size;
		}

		return compressedSize += tailEndSize;

	}
}
