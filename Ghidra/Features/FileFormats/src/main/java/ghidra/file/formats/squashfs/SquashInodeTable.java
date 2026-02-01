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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SquashInodeTable {

	// An array of inodes indexed by their inode number
	private final SquashInode[] inodes;

	// The offset in the uncompressed inode table where the root inode begins
	private long rootInodeOffset;

	// The root inode of the archive
	private SquashInode rootInode;

	/**
	 * Represents the inode table within the SquashFS archive
	 * @param reader A binary reader for the entire SquashFS archive
	 * @param superBlock The SuperBlock for the current archive
	 * @param monitor Monitor to allow the user to cancel the load
	 * @throws IOException Any read operation failure
	 * @throws CancelledException Archive load was cancelled
	 */
	public SquashInodeTable(BinaryReader reader, SquashSuperBlock superBlock, TaskMonitor monitor)
			throws IOException, CancelledException {

		// Read from the start of the inode table
		reader.setPointerIndex(superBlock.getInodeTableStart());

		// The reader will now contain ONLY the uncompressed bytes of the inode table
		reader =
			decompressInodeTable(reader, superBlock.getDirectoryTableStart(), superBlock, monitor);

		// Create inode array. inode count is off by one
		inodes = new SquashInode[(int) superBlock.getInodeCount() + 1];

		// inodes begin indexing at 1, so 0th inode is null
		inodes[0] = null;

		// While there are still inodes to process in the decompressed stream
		while (reader.hasNext()) {

			// Check if the user cancelled the load
			monitor.checkCancelled();

			boolean isRootInode = reader.getPointerIndex() == rootInodeOffset;

			// Get the inode type without advancing the reader
			short inodeType = reader.peekNextShort();
			SquashInode tempInode;

			// Create a new inode based on the inode type
			switch (inodeType) {
				case SquashConstants.INODE_TYPE_BASIC_FILE:
					tempInode = new SquashBasicFileInode(reader, superBlock, false);
					break;
				case SquashConstants.INODE_TYPE_EXTENDED_FILE:
					tempInode = new SquashExtendedFileInode(reader, superBlock);
					break;
				case SquashConstants.INODE_TYPE_BASIC_DIRECTORY:
					tempInode = new SquashBasicDirectoryInode(reader, superBlock, false);
					break;
				case SquashConstants.INODE_TYPE_EXTENDED_DIRECTORY:
					tempInode = new SquashExtendedDirectoryInode(reader, superBlock);
					break;
				case SquashConstants.INODE_TYPE_BASIC_SYMLINK:
					tempInode = new SquashSymlinkInode(reader, superBlock, false);
					break;
				case SquashConstants.INODE_TYPE_EXTENDED_SYMLINK:
					tempInode = new SquashSymlinkInode(reader, superBlock, true);
					break;

				default:
					// All other inode types are effectively skipped, but processed for info
					tempInode = new SquashOtherInode(reader, superBlock, inodeType);
			}

			// Validate the inode number, then add the given inode to the list (indexed by its number)
			int tempInodeNumber = tempInode.getNumber();
			if (tempInodeNumber == 0 || tempInodeNumber > superBlock.getInodeCount()) {
				throw new IOException("Invalid inode number found: " + tempInodeNumber);
			}
			inodes[tempInode.getNumber()] = tempInode;

			// Record root inode if needed
			if (isRootInode) {
				rootInode = tempInode;
			}
		}
	}

	public SquashInode[] getInodes() {
		return inodes;
	}

	public SquashInode getInodeByNumber(int inodeNumber) {
		return inodes[inodeNumber];
	}

	public SquashInode getRootInode() {
		return rootInode;
	}

	/**
	 * Build the parent/child relationships between inodes
	 * @param monitor Monitor to allow the user to cancel the load
	 * @throws CancelledException Archive load was cancelled
	 */
	public void buildRelationships(TaskMonitor monitor) throws CancelledException {

		// Work backwards (last inode is root) and skip the first inode
		for (int i = inodes.length - 1; i > 0; i--) {

			// Check if the user cancelled the load
			monitor.checkCancelled();

			SquashInode currentInode = inodes[i];

			// Only directory inodes have parent/child relationships
			if (currentInode.isDir()) {
				SquashBasicDirectoryInode dirInode = (SquashBasicDirectoryInode) currentInode;

				// Check if the parent of the current node is the root node
				if (!dirInode.isParentRoot()) {
					dirInode.setParent(inodes[dirInode.getParentInodeNumber()]);
				}
			}
		}
	}

	/**
	 * Decompress the inode table and record the root inode
	 * @param reader The BinaryReader pointed to the start of the section
	 * @param endAddress The address the section ends at
	 * @param superBlock The SuperBlock for the current archive
	 * @param monitor Monitor to allow the user to cancel the load
	 * @return A BinaryReader containing ONLY the uncompressed bytes of the section
	 * @throws IOException Any read operation failure
	 * @throws CancelledException Archive load was cancelled
	 */
	private BinaryReader decompressInodeTable(BinaryReader reader, long endAddress,
			SquashSuperBlock superBlock, TaskMonitor monitor)
			throws IOException, CancelledException {

		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		// Keep track of how many bytes result from decompression
		int totalUncompressedBytes = 0;

		// Continue reading until the end of the section is reached
		while (reader.getPointerIndex() < endAddress) {

			// Check if the user cancelled the load
			monitor.checkCancelled();

			// If processing the inode table, check if the current metadata block contains the root inode
			if ((reader.getPointerIndex() - superBlock.getInodeTableStart()) == superBlock
					.getRootInodeBlockLocation()) {

				// Tell the inode table the root inode location within the uncompressed bytes
				rootInodeOffset = totalUncompressedBytes + superBlock.getRootInodeOffset();
			}

			// Decompress the current metablock
			byte[] bytes =
				SquashUtils.decompressBlock(reader, superBlock.getCompressionType(), monitor);

			// Add bytes to the stream
			bos.write(bytes);
			totalUncompressedBytes += bytes.length;
		}

		// Convert the output stream into a BinaryReader and return
		return SquashUtils.byteArrayToReader(bos.toByteArray());
	}
}
