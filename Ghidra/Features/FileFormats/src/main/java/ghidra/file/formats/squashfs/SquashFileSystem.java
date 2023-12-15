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

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;
import java.io.OutputStream;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "squashfs", description = "SquashFS", factory = SquashFileSystemFactory.class)
public class SquashFileSystem extends AbstractFileSystem<SquashedFile> {

	private ByteProvider provider;
	private BinaryReader reader;
	private SquashSuperBlock superBlock;

	public SquashFileSystem(FSRLRoot fsFSRL, ByteProvider provider, FileSystemService fsService) {
		super(fsFSRL, fsService);
		fsIndex = new FileSystemIndexHelper<>(this, fsFSRL);

		this.provider = provider;

		// BinaryReader representing the entire archive
		// Squash versions after 3.0 (2006) should be little endian
		reader = new BinaryReader(provider, true /* LE */);
	}

	public void mount(TaskMonitor monitor) throws IOException, CancelledException {
		monitor.setMessage("Opening " + SquashFileSystem.class.getSimpleName() + "...");

		// Get the super block information for how to process the archive
		superBlock = new SquashSuperBlock(reader);

		// Parse the fragment table
		SquashFragmentTable fragmentTable = new SquashFragmentTable(reader, superBlock, monitor);

		// Parse the directory table
		SquashDirectoryTable directoryTable =
			new SquashDirectoryTable(reader, superBlock, fragmentTable, monitor);

		// Parse the inode table
		SquashInodeTable inodes = new SquashInodeTable(reader, superBlock, monitor);

		// Build the parent/child relationships with the inodes
		inodes.buildRelationships(monitor);

		// The directory table entries point to inodes for additional information. Link the inodes
		// to these entries
		directoryTable.assignInodes(inodes, monitor);

		// Give file structure to Ghidra to present to the user
		SquashUtils.buildDirectoryStructure(fragmentTable, directoryTable, inodes, fsIndex,
			monitor);
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {

		SquashedFile squashFile = fsIndex.getMetadata(file);

		long fileSize = -1;

		if (squashFile != null) {
			fileSize = squashFile.getUncompressedSize();
		}

		// Decompress the file either to memory or storage and return a ByteProvider of the resulting file
		return fsService.getDerivedByteProviderPush(provider.getFSRL(), file.getFSRL(),
			file.getName(), fileSize, (os) -> {
				extractFileToStream(os, file, monitor);
			}, monitor);
	}

	/**
	 * Convert the given SquashFS file into a stream of bytes
	 * @param os The stream to write file data to
	 * @param file The file to convert
	 * @param monitor Monitor to allow the user to cancel the load
	 * @throws IOException Any read operation failure
	 * @throws CancelledException File load was cancelled
	 */
	public void extractFileToStream(OutputStream os, GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {

		// If the current file is a symlink, try to follow it
		file = followSymLink(file, 0);

		SquashedFile squashedFile = fsIndex.getMetadata(file);

		if (squashedFile == null) {
			throw new IOException("Could not find SquashedFile associated with the symlink target");
		}

		// Stop if the associated inode is not a file
		SquashInode inode = squashedFile.getInode();
		if (!(inode.isFile())) {
			throw new IOException("Inode is not a file");
		}

		// Get the associated file inode
		SquashBasicFileInode fileInode = (SquashBasicFileInode) inode;

		// Keep track of the total number of decompressed bytes for progress tracking reasons
		long totalUncompressedBytes = 0;

		// Set the monitor's completion point to be all bytes processed
		monitor.initialize(fileInode.getFileSize());

		// Process all the blocks comprising the file
		totalUncompressedBytes += processFileBlocks(squashedFile, fileInode, os, monitor);

		// Grab the tail end of the file if it exists
		if (squashedFile.hasFragment()) {
			totalUncompressedBytes += processTailEnd(squashedFile, fileInode, os, monitor);
		}

		// Monitor should be 100% at this point
		monitor.setProgress(totalUncompressedBytes);
	}

	/**
	 * Given a GFile representing a symlink, return the destination GFile, recursing into referenced
	 * symlinks as needed. If the given file is not a symlink, it will be returned
	 * @param symLinkFile The file representing a symlink containing the target
	 * @param depth The current recursion depth to prevent recursing too far
	 * @return The destination file
	 * @throws IOException Issues relating to locating a symlink target
	 */
	private GFile followSymLink(GFile symLinkFile, int depth) throws IOException {

		// Check if a file was supplied properly
		if (symLinkFile == null) {
			return null;
		}

		// Get the path associated with the given symlink
		String path = getSymLinkPath(symLinkFile);

		// If path is null, then the given file is not a symlink and should be returned as the destination
		if (path == null) {
			return symLinkFile;
		}

		// Make sure to not follow symlinks too far
		if (depth > SquashConstants.MAX_SYMLINK_DEPTH) {
			throw new IOException("Did not find symlink destination after max traversal");
		}

		// Start with the parent at the root of the archive, as all paths will be absolute
		GFile currentFile = symLinkFile.getParentFile();

		// Split up the path into its parts
		List<String> pathParts = new ArrayList<String>(Arrays.asList(path.split("/")));

		// Future references to "." are redundant, so remove them along with any blank parts
		pathParts.removeIf(part -> part.contentEquals(".") || part.isBlank());

		// Iterate over all parts of the input path, removing portions as ".." appears
		ListIterator<String> iterator = pathParts.listIterator();
		while (iterator.hasNext()) {

			// Get the next portion of the path
			String currentPart = iterator.next();

			// If the link references up a directory
			if (currentPart.equals("..")) {

				// Move up a directory
				currentFile = currentFile.getParentFile();

			}
			else {

				// Get the file representing the next portion of the path
				currentFile = fsIndex.lookup(currentFile, currentPart, null);

				// Determine if the current file is a symlink and follow it if so
				currentFile = followSymLink(currentFile, depth + 1);
			}

			// Check if the lookup failed
			if (currentFile == null) {
				throw new IOException("Could not find file within the given parent directory");
			}

			// Keep track of the depth
			depth++;
		}

		// Return GFile representing the destination of the symlink
		return currentFile;
	}

	/**
	 * If the given file is a symlink, return the path it points to (null if file is not a symlink)
	 * @param file The file to check
	 * @return The symlink path
	 * @throws IOException There was no SquashedFile for the given file
	 */
	private String getSymLinkPath(GFile file) throws IOException {

		// Get the associated SquashedFile and make sure it is not null
		SquashedFile possibleSymLinkFile = fsIndex.getMetadata(file);
		if (possibleSymLinkFile == null) {
			throw new IOException("Cannot retrieve SquashedFile associated with the given file");
		}

		// Check if the current part is a symlink
		if (possibleSymLinkFile.getInode().isSymLink()) {
			// Get and convert the associated inode
			SquashSymlinkInode symLinkInode = (SquashSymlinkInode) possibleSymLinkFile.getInode();

			// Get the target path
			return symLinkInode.getPath();
		}

		// If the file is not a symlink, return null
		return null;
	}

	/**
	 * Decompress (if needed) all data block associated with the given file and write to OutputStream
	 * @param squashedFile The file to process
	 * @param fileInode The inode associated with the file
	 * @param os The stream to write to
	 * @param monitor The monitor to keep track of the progress with
	 * @return The number of uncompressed bytes the blocks used
	 * @throws CancelledException The user cancelled the file read
	 * @throws IOException Any read error
	 */
	private int processFileBlocks(SquashedFile squashedFile, SquashBasicFileInode fileInode,
			OutputStream os, TaskMonitor monitor) throws CancelledException, IOException {
		int[] blockSizes = fileInode.getBlockSizes();

		// Location of starting block
		long location = fileInode.getStartBlockOffset();

		int blockUncompressedBytes = 0;

		// Handle the primary bytes of the file
		for (int blockSizeHeader : blockSizes) {

			// Check if the user cancelled the load
			monitor.checkCancelled();

			// Set the monitor's progress
			monitor.setProgress(blockUncompressedBytes);

			// Extract data from the block size header
			boolean isCompressed =
				(blockSizeHeader & SquashConstants.DATABLOCK_COMPRESSED_MASK) == 0;
			long size = blockSizeHeader & ~SquashConstants.DATABLOCK_COMPRESSED_MASK;

			// If we encounter a block with size zero, we write a full block of zeros to the output
			if (size <= 0) {

				// Write all zeroes for the given blockSize
				size = superBlock.getBlockSize();
				os.write(new byte[(int) size]);

				// Increment the progress
				blockUncompressedBytes += size;
				continue;
			}

			// Set the reader to read from the block start location
			reader.setPointerIndex(location);

			// Move location to the start of the next block for next iteration
			location += size;

			byte[] buffer = null;

			// Check for compression
			if (isCompressed) {
				buffer = SquashUtils.decompressBytes(reader, (int) size,
					superBlock.getCompressionType(), monitor);
			}
			else {
				buffer = reader.readNextByteArray((int) size);
			}

			// Write to the output and increment progress
			os.write(buffer);
			blockUncompressedBytes += buffer.length;
		}

		return blockUncompressedBytes;
	}

	/**
	 * Decompress (if needed) the tail end of the given file and write to OutputStream
	 * @param squashedFile The file to process
	 * @param fileInode The inode associated with the file
	 * @param os The stream to write to
	 * @param monitor The monitor to keep track of the progress with
	 * @return The number of uncompressed bytes the tail end used
	 * @throws CancelledException The user cancelled the file read
	 * @throws IOException Any read error
	 */
	private int processTailEnd(SquashedFile squashedFile, SquashBasicFileInode fileInode,
			OutputStream os, TaskMonitor monitor) throws CancelledException, IOException {

		SquashFragment fragment = squashedFile.getFragment();

		byte[] buffer = null;

		if (fragment.isCompressed()) {

			// Set the pointer to where (relative to the start of the archive) the fragment starts
			reader.setPointerIndex(fragment.getFragmentOffset());

			// Decompress the fragment into a byte array
			buffer = SquashUtils.decompressBytes(reader, (int) fragment.getFragmentSize(),
				superBlock.getCompressionType(), monitor);

			// Remove non-relevant portion of the fragment block
			buffer = Arrays.copyOfRange(buffer, fileInode.getBlockOffset(),
				fileInode.getBlockOffset() + fileInode.getTailEndSize());
		}
		else {
			// Set the pointer to start of the tail end of file within the fragment
			reader.setPointerIndex(fragment.getFragmentOffset() + fileInode.getBlockOffset());

			// Read only relevant the portion of the fragment
			buffer = reader.readNextByteArray(fileInode.getTailEndSize());
		}

		// Write to the output and increment progress
		os.write(buffer);
		return buffer.length;
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {

		FileAttributes result = new FileAttributes();

		SquashedFile squashedFile = fsIndex.getMetadata(file);

		if (squashedFile != null) {

			SquashInode inode = squashedFile.getInode();

			// Add additional attributes to the root directory
			if (fsIndex.getRootDir().equals(file)) {
				result.add("Compression used", superBlock.getCompressionTypeString());
				result.add("Block size", superBlock.getBlockSize());
				result.add("Inode count", superBlock.getInodeCount());
				result.add("Fragment count", superBlock.getTotalFragments());
				result.add("SquashFS version", superBlock.getVersionString());
				result.add(MODIFIED_DATE_ATTR, new Date(superBlock.getModTime()));
			}
			else {
				result.add(MODIFIED_DATE_ATTR, new Date(inode.getModTime()));
			}

			// Add general attributes
			result.add(NAME_ATTR, squashedFile.getName());
			result.add(FSRL_ATTR, file.getFSRL());

			// Add file-related attributes
			if (inode.isFile()) {
				SquashBasicFileInode fileInode = (SquashBasicFileInode) inode;

				result.add(SIZE_ATTR, squashedFile.getUncompressedSize());
				result.add(COMPRESSED_SIZE_ATTR, fileInode.getCompressedFileSize());

			}
			else if (inode.isSymLink()) {

				SquashSymlinkInode symLinkInode = (SquashSymlinkInode) inode;
				result.add(SYMLINK_DEST_ATTR, symLinkInode.getPath());

			}
		}

		return result;
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		fsIndex.clear();
		if (provider != null) {
			provider.close();
			provider = null;
		}
	}
}
