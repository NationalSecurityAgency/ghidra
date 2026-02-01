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
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SquashDirectoryTable {

	// A map of directory table entries listed by the offset in which they appear within
	// the uncompressed directory table
	private final Map<Long, SquashDirectoryTableHeader> headersByOffset;

	// Map of block offsets into the original archive to the offset into the uncompressed directory table
	private final Map<Long, Long> archiveToReaderOffsets;

	/**
	 * Represents the directory table within the SquashFS archive
	 * @param reader A binary reader for the entire SquashFS archive
	 * @param superBlock The SuperBlock for the current archive
	 * @param fragTable The processed fragment table for the archive
	 * @param monitor Monitor to allow the user to cancel the load
	 * @throws IOException Any read operation failure
	 * @throws CancelledException Archive load was cancelled
	 */
	public SquashDirectoryTable(BinaryReader reader, SquashSuperBlock superBlock,
			SquashFragmentTable fragTable, TaskMonitor monitor)
			throws IOException, CancelledException {

		// Read from the start of the directory table
		reader.setPointerIndex(superBlock.getDirectoryTableStart());

		// The end address of the directory table depends on the number of fragments in the archive
		long endOfDirTable;
		if (!superBlock.isFragmentsUnused() && superBlock.getTotalFragments() > 0) {
			endOfDirTable = fragTable.getMinFragPointer();
		}
		else {
			endOfDirTable = superBlock.getFragmentTableStart();
		}

		headersByOffset = new HashMap<Long, SquashDirectoryTableHeader>();
		archiveToReaderOffsets = new HashMap<Long, Long>();

		// The reader will now contain ONLY the uncompressed bytes of the directory table
		reader = decompressDirectoryTable(reader, endOfDirTable, superBlock.getCompressionType(),
			monitor);

		// While there are still additional blocks to process
		while (reader.hasNext()) {

			// Check if the user cancelled the load
			monitor.checkCancelled();

			// Create a new header to the map indexed by the reader's current position
			headersByOffset.put(reader.getPointerIndex(),
				new SquashDirectoryTableHeader(reader, superBlock, monitor));
		}
	}

	/**
	 * This method will assign each directory entry to an inode
	 * @param inodeTable The object representing all inodes in the archive
	 * @param monitor Monitor to allow the user to cancel the load
	 * @throws CancelledException Archive load was cancelled
	 */
	public void assignInodes(SquashInodeTable inodeTable, TaskMonitor monitor)
			throws CancelledException {

		// For each of the directory headers in the table
		for (long offset : headersByOffset.keySet()) {

			// Check if the user cancelled the load
			monitor.checkCancelled();

			SquashDirectoryTableHeader header = headersByOffset.get(offset);

			// Assign the proper inode to each of the directory entries under the header
			for (SquashDirectoryTableEntry child : header.getEntries()) {
				SquashInode inode = inodeTable.getInodeByNumber(child.getInodeNumber());
				inode.setDirectoryTableEntry(child);
			}

		}
	}

	/**
	 * Get the headers associated with the given directory inode
	 * @param inode The inode to search by
	 * @return A list of headers that are associated with the given inode
	 */
	public List<SquashDirectoryTableHeader> getHeaders(SquashBasicDirectoryInode inode) {

		List<SquashDirectoryTableHeader> headers = new ArrayList<SquashDirectoryTableHeader>();

		// Set search boundaries
		long blockStart = archiveToReaderOffsets.get((long) inode.getIndex());
		long start = blockStart + inode.getOffset();
		long end = start + inode.getUncompressedSize() - 3; // Account for "." and ".." entries

		// Add all headers that start within the bounds given to be returned
		for (long offset : headersByOffset.keySet()) {
			if (offset >= start && offset < end) {
				headers.add(headersByOffset.get(offset));
			}

		}

		return headers;
	}

	/**
	 * Decompress the directory table and log block positions
	 * @param reader The BinaryReader pointed to the start of the section
	 * @param endAddress The address the section ends at
	 * @param compressionType The compression type if the archive
	 * @param monitor Monitor to allow the user to cancel the load
	 * @return A BinaryReader containing ONLY the uncompressed bytes of the section
	 * @throws IOException Any read operation failure
	 * @throws CancelledException Archive load was cancelled
	 */
	private BinaryReader decompressDirectoryTable(BinaryReader reader, long endAddress,
			int compressionType, TaskMonitor monitor) throws IOException, CancelledException {

		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		// Keep track of how many bytes result from decompression
		int totalUncompressedBytes = 0;

		long directoryTableStart = reader.getPointerIndex();

		// Continue reading until the end of the section is reached
		while (reader.getPointerIndex() < endAddress) {

			// Check if the user cancelled the load
			monitor.checkCancelled();

			long startOfBlockOffset = reader.getPointerIndex() - directoryTableStart;

			// Decompress the current metablock
			byte[] bytes = SquashUtils.decompressBlock(reader, compressionType, monitor);
			bos.write(bytes);

			archiveToReaderOffsets.put(startOfBlockOffset, (long) totalUncompressedBytes);
			totalUncompressedBytes += bytes.length;
		}

		// Convert the output stream into a BinaryReader and return
		return SquashUtils.byteArrayToReader(bos.toByteArray());
	}

}
