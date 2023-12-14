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
import java.io.InputStream;
import java.util.List;

import org.apache.commons.compress.compressors.deflate.DeflateCompressorInputStream;
import org.apache.commons.compress.compressors.lz4.BlockLZ4CompressorInputStream;
import org.apache.commons.compress.compressors.xz.XZCompressorInputStream;
import org.tukaani.xz.LZMAInputStream;

import ghidra.app.util.bin.*;
import ghidra.file.formats.gzip.GZipConstants;
import ghidra.formats.gfilesystem.FileSystemIndexHelper;
import ghidra.formats.gfilesystem.GFile;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SquashUtils {

	/**
	 * Match the first four of the given bytes against the SquashFS magic bytes
	 * @param bytes The first bytes of a file (must have >= 4 bytes)
	 * @return Whether or not the bytes match the SquashFS magic
	 */
	public static boolean isSquashFS(byte[] bytes) {
		return bytes.length >= GZipConstants.MAGIC_BYTES.length &&
			bytes[0] == SquashConstants.MAGIC[0] && bytes[1] == SquashConstants.MAGIC[1] &&
			bytes[2] == SquashConstants.MAGIC[2] && bytes[3] == SquashConstants.MAGIC[3];
	}

	/**
	 * Decompress a metablock into a byte array
	 * @param reader The BinaryReader pointed to the start of the section
	 * @param compressionType The compression type if the archive
	 * @param monitor Monitor to allow the user to cancel the load
	 * @return A BinaryReader containing ONLY the uncompressed bytes of the section
	 * @throws IOException Any read operation failure
	 * @throws CancelledException Archive load was cancelled
	 */
	public static byte[] decompressBlock(BinaryReader reader, int compressionType,
			TaskMonitor monitor) throws IOException, CancelledException {

		SquashMetablock header = new SquashMetablock(reader);

		// Only perform decompression if the block is compressed
		if (header.isCompressed()) {
			return decompressBytes(reader, header.getBlockSize(), compressionType, monitor);
		}

		return reader.readNextByteArray(header.getBlockSize());
	}

	/**
	 * Create a BinaryReader from the given byte array
	 * @param bytes The source bytes
	 * @return A BinaryReader for the source byte array
	 */
	public static BinaryReader byteArrayToReader(byte[] bytes) {
		ByteProvider newProvider = new ByteArrayProvider(bytes);
		return new BinaryReader(newProvider, true /* LE */);
	}

	/**
	 * Decompress the given bytes
	 * @param reader A BinaryReader pointed at the start of the bytes to be decompressed
	 * @param length The amount of bytes to decompress
	 * @param compressionType The type of compression being used by the archive
	 * @param monitor Monitor to allow the user to cancel the load
	 * @return A byte array containing the decompressed bytes
	 * @throws IOException Any kind of decompression/read error
	 * @throws CancelledException Archive load was cancelled
	 */
	public static byte[] decompressBytes(BinaryReader reader, int length, int compressionType,
			TaskMonitor monitor) throws IOException, CancelledException {

		// Check if the user cancelled the load
		monitor.checkCancelled();

		// Create InputStream containing ONLY the source compressed bytes
		InputStream is = getSubInputStream(reader, length);

		// Convert the InputStream into a decompression stream
		try (InputStream decompressedInputStream = getDecompressionStream(is, compressionType)) {

			// Decompress and return all bytes from the stream
			return decompressedInputStream.readAllBytes();
		}
		finally {
			is.close();
		}
	}

	/**
	 * Create an InputStream containing only the next n bytes from the given reader
	 * @param reader A BinaryReader pointed at the start of the bytes to be read
	 * @param length The amount of bytes to be read
	 * @return An InputStream containing n bytes
	 */
	public static InputStream getSubInputStream(BinaryReader reader, long length) {

		// Get the start of the stream and advance the reader position
		long start = reader.getPointerIndex();
		reader.setPointerIndex(start + length);

		// Create and the input stream
		ByteProvider bp = reader.getByteProvider();
		ByteProviderWrapper subBP = new ByteProviderWrapper(bp, start, length);
		return new ByteProviderInputStream.ClosingInputStream(subBP);
	}

	/**
	 * Convert the given InputStream into the appropriate decompression InputStream for the data
	 * @param is InputStream containing the compressed source bytes
	 * @param compressionType The type of compression the archive uses
	 * @return An appropriate decompression InputStream for the data
	 * @throws IOException Conversion failed (likely due to unsupported compression algorithm)
	 */
	public static InputStream getDecompressionStream(InputStream is, int compressionType)
			throws IOException {

		// Based on the supplied compression type, return the appropriate type of CompressorInputStream
		switch (compressionType) {
			case SquashConstants.COMPRESSION_TYPE_GZIP:
				return new DeflateCompressorInputStream(is);
			case SquashConstants.COMPRESSION_TYPE_LZMA:
				LZMAInputStream lzmaIn = new LZMAInputStream(is);
				lzmaIn.enableRelaxedEndCondition();
				return lzmaIn;
			case SquashConstants.COMPRESSION_TYPE_LZO:
				throw new IOException("LZO compression is not supported");
			case SquashConstants.COMPRESSION_TYPE_XZ:
				return new XZCompressorInputStream(is);
			case SquashConstants.COMPRESSION_TYPE_LZ4:
				return new BlockLZ4CompressorInputStream(is);
			case SquashConstants.COMPRESSION_TYPE_ZSTD:
				throw new IOException("ZSTD compression is not supported");
			default:
				throw new IOException("Supplied compression type (code: " + compressionType +
					") was not recognized. ");
		}
	}

	/**
	 * Assemble the directory structure of the archive
	 * @param fragTable The processed fragment table of the archive
	 * @param dirTable The processed directory table of the archive
	 * @param inodes The processed inode table of the archive
	 * @param fsih An index helper
	 * @param monitor Monitor to allow the user to cancel the load
	 * @throws CancelledException Archive load was cancelled
	 * @throws IOException Root inode was not a directory
	 */
	public static void buildDirectoryStructure(SquashFragmentTable fragTable,
			SquashDirectoryTable dirTable, SquashInodeTable inodes,
			FileSystemIndexHelper<SquashedFile> fsih, TaskMonitor monitor)
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
						fsih.getRootDir(), fsih, monitor);
				}
			}
		}
		else {
			// If root is NOT a directory, stop processing
			throw new IOException("Root inode was not a directory!");
		}
	}

	/**
	 * Recursively assign paths to each of the inodes
	 * @param dirTable The processed directory table of the archive
	 * @param entry The directory table entry currently being processed
	 * @param inodes An array of inodes within the archive
	 * @param parentDir The parent of the current entry
	 * @param fsih An index helper
	 * @param monitor Monitor to allow the user to cancel the load
	 * @throws CancelledException Archive load was cancelled
	 * @throws IOException Entry found with an invalid inode number
	 */
	private static void assignPathsRecursively(SquashFragmentTable fragTable,
			SquashDirectoryTable dirTable, SquashDirectoryTableEntry entry, SquashInode[] inodes,
			GFile parentDir, FileSystemIndexHelper<SquashedFile> fsih, TaskMonitor monitor)
			throws CancelledException, IOException {

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
			GFile dirGFile = fsih.storeFileWithParent(entry.getFileName(), parentDir,
				inode.getNumber(), true, -1, squashedDirFile);

			// Get the directory headers for the current inode and process each entry within them
			List<SquashDirectoryTableHeader> headers = dirTable.getHeaders(dirInode);
			for (SquashDirectoryTableHeader header : headers) {

				// For each sub-directory, recurse downward and add each file/directory encountered
				List<SquashDirectoryTableEntry> entries = header.getEntries();
				for (SquashDirectoryTableEntry currentEntry : entries) {
					assignPathsRecursively(fragTable, dirTable, currentEntry, inodes, dirGFile,
						fsih, monitor);
				}
			}
		}
		else if (inode.isFile()) {

			// Treat as file inode
			SquashBasicFileInode fileInode = (SquashBasicFileInode) inode;

			SquashFragment fragment = fragTable.getFragment(fileInode.getFragmentIndex());

			// Store the current file
			fsih.storeFileWithParent(entry.getFileName(), parentDir, fileInode.getNumber(), false,
				fileInode.getFileSize(), new SquashedFile(fileInode, fragment));
		}
		else if (inode.isSymLink()) {

			// Treat as symbolic link inode
			SquashSymlinkInode symLinkInode = (SquashSymlinkInode) inode;

			// Store symlink as file. Lookup handled when getting ByteProvider
			fsih.storeFileWithParent(entry.getFileName(), parentDir, symLinkInode.getNumber(),
				false, 0, new SquashedFile(symLinkInode, null));

		}
		else {
			Msg.info(SquashUtils.class,
				"Inode #" + inode.getNumber() + " is not a file or directory. Skipping...");
		}
	}
}
