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
import java.util.Arrays;
import java.util.List;

import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.formats.gfilesystem.fileinfo.FileType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "squashfs", description = "SquashFS", factory = SquashFileSystemFactory.class)
public class SquashFileSystem extends AbstractFileSystem<SquashedFile> {

	private ByteProvider provider;
	private BinaryReader reader;
	private SquashSuperBlock superBlock;

	public SquashFileSystem(FSRLRoot fsFSRL, FileSystemService fsService) {
		super(fsFSRL, fsService);
		fsIndex = new FileSystemIndexHelper<>(this, fsFSRL);
	}

	public void mount(ByteProvider provider, TaskMonitor monitor)
			throws IOException, CancelledException {
		monitor.setMessage("Opening " + SquashFileSystem.class.getSimpleName() + "...");

		this.provider = provider;

		// BinaryReader representing the entire archive
		// Squash versions after 3.0 (2006) should be little endian
		reader = new BinaryReader(provider, true /* LE */);

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
		buildDirectoryStructure(fragmentTable, directoryTable, inodes, monitor);
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
		file = fsIndex.resolveSymlinks(file);

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

		// Add general attributes
		result.add(NAME_ATTR, file.getName());
		result.add(FSRL_ATTR, file.getFSRL());
		result.add(PATH_ATTR, FilenameUtils.getFullPathNoEndSeparator(file.getPath()));

		SquashedFile squashedFile = fsIndex.getMetadata(file);
		Object squashInfo = fsIndex.getRootDir().equals(file) ? superBlock
				: squashedFile != null ? squashedFile.getInode() : null;

		switch (squashInfo) {
			case SquashSuperBlock sb: // superBlock also avail as member var
				result.add("Compression used", superBlock.getCompressionTypeString());
				result.add("Block size", superBlock.getBlockSize());
				result.add("Inode count", superBlock.getInodeCount());
				result.add("Fragment count", superBlock.getTotalFragments());
				result.add("SquashFS version", superBlock.getVersionString());
				result.add(MODIFIED_DATE_ATTR, superBlock.getModTimeAsDate());
				break;
			case SquashBasicFileInode fileInode:
				result.add(SIZE_ATTR, squashedFile.getUncompressedSize());
				result.add(COMPRESSED_SIZE_ATTR, fileInode.getCompressedFileSize());
				result.add(FILE_TYPE_ATTR, fileInode.isDir() ? FileType.DIRECTORY : FileType.FILE);
				result.add(MODIFIED_DATE_ATTR, fileInode.getModTimeAsDate());
				result.add(UNIX_ACL_ATTR, (long) fileInode.getPermissions());
				break;
			case SquashBasicDirectoryInode dirInode:
				result.add(FILE_TYPE_ATTR, FileType.DIRECTORY);
				result.add(MODIFIED_DATE_ATTR, dirInode.getModTimeAsDate());
				result.add(UNIX_ACL_ATTR, (long) dirInode.getPermissions());
				break;
			case SquashSymlinkInode symlinkInode:
				result.add(SYMLINK_DEST_ATTR, symlinkInode.getPath());
				result.add(FILE_TYPE_ATTR, FileType.SYMBOLIC_LINK);
				result.add(MODIFIED_DATE_ATTR, symlinkInode.getModTimeAsDate());
				result.add(UNIX_ACL_ATTR, (long) symlinkInode.getPermissions());
				break;
			default:
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
			reader = null;
		}
	}

	private void buildDirectoryStructure(SquashFragmentTable fragTable,
			SquashDirectoryTable dirTable, SquashInodeTable inodes, TaskMonitor monitor)
			throws CancelledException, IOException {

		SquashInode[] inodeArray = inodes.getInodes();

		SquashInode rootInode = inodes.getRootInode();

		// Make sure the root inode is a directory
		if (rootInode != null && rootInode.isDir()) {

			// Treat root inode as a directory inode
			SquashBasicDirectoryInode dirInode = (SquashBasicDirectoryInode) rootInode;

			// For each header associated with the root inode, process all entries
			List<SquashDirectoryTableHeader> headers = dirTable.getHeaders(dirInode);

			if (headers.size() == 0) {
				throw new IOException("Unable to find headers for the root directory");
			}

			for (SquashDirectoryTableHeader header : headers) {

				// For all files/directories immediately under the root
				List<SquashDirectoryTableEntry> entries = header.getEntries();
				for (SquashDirectoryTableEntry entry : entries) {

					// Recurse down the directory tree, storing directories and files
					assignPathsRecursively(fragTable, dirTable, entry, inodeArray,
						fsIndex.getRootDir(), monitor);
				}
			}
		}
		else {
			// If root is NOT a directory, stop processing
			throw new IOException("Root inode was not a directory!");
		}
	}

	private void assignPathsRecursively(SquashFragmentTable fragTable,
			SquashDirectoryTable dirTable, SquashDirectoryTableEntry entry, SquashInode[] inodes,
			GFile parentDir, TaskMonitor monitor) throws CancelledException, IOException {

		// Check if the user cancelled the load
		monitor.checkCancelled();

		// Validate the inode number of the current entry
		if (entry == null || entry.getInodeNumber() < 1 || entry.getInodeNumber() > inodes.length) {
			throw new IOException(
				"Entry found with invalid inode number: " + entry.getInodeNumber());
		}

		// Get the inode for the current entry
		SquashInode inode = inodes[entry.getInodeNumber()];

		// If the inode is a directory, recurse downward. Otherwise, just store the file
		if (inode.isDir()) {

			// Treat as directory inode
			SquashBasicDirectoryInode dirInode = (SquashBasicDirectoryInode) inode;
			// Create and store a "file" representing the current directory
			SquashedFile squashedDirFile = new SquashedFile(dirInode, null);
			GFile dirGFile = fsIndex.storeFileWithParent(entry.getFileName(), parentDir,
				inode.getNumber(), true, -1, squashedDirFile);

			// Get the directory headers for the current inode and process each entry within them
			List<SquashDirectoryTableHeader> headers = dirTable.getHeaders(dirInode);
			for (SquashDirectoryTableHeader header : headers) {

				// For each sub-directory, recurse downward and add each file/directory encountered
				List<SquashDirectoryTableEntry> entries = header.getEntries();
				for (SquashDirectoryTableEntry currentEntry : entries) {
					assignPathsRecursively(fragTable, dirTable, currentEntry, inodes, dirGFile,
						monitor);
				}
			}
		}
		else if (inode.isFile()) {

			// Treat as file inode
			SquashBasicFileInode fileInode = (SquashBasicFileInode) inode;

			SquashFragment fragment = fragTable.getFragment(fileInode.getFragmentIndex());

			// Store the current file
			fsIndex.storeFileWithParent(entry.getFileName(), parentDir, fileInode.getNumber(),
				false, fileInode.getFileSize(), new SquashedFile(fileInode, fragment));
		}
		else if (inode.isSymLink()) {

			// Treat as symbolic link inode
			SquashSymlinkInode symLinkInode = (SquashSymlinkInode) inode;

			fsIndex.storeSymlinkWithParent(entry.getFileName(), parentDir, symLinkInode.getNumber(),
				symLinkInode.getPath(), 0, new SquashedFile(symLinkInode, null));
		}
		else {
			Msg.info(SquashUtils.class,
				"Inode #" + inode.getNumber() + " is not a file or directory. Skipping...");
		}
	}

}
