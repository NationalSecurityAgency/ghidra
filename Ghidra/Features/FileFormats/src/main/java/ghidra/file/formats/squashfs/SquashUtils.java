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
import java.util.Arrays;

import org.apache.commons.compress.compressors.deflate.DeflateCompressorInputStream;
import org.apache.commons.compress.compressors.lz4.BlockLZ4CompressorInputStream;
import org.apache.commons.compress.compressors.xz.XZCompressorInputStream;
import org.tukaani.xz.LZMAInputStream;

import ghidra.app.util.bin.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SquashUtils {

	/**
	 * Match the first four of the given bytes against the SquashFS magic bytes
	 * @param bytes The first bytes of a file (must have >= 4 bytes)
	 * @return Whether or not the bytes match the SquashFS magic
	 */
	public static boolean isSquashFS(byte[] bytes) {
		return bytes.length >= SquashConstants.MAGIC.length && Arrays.equals(SquashConstants.MAGIC,
			0, SquashConstants.MAGIC.length, bytes, 0, SquashConstants.MAGIC.length);
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

}
