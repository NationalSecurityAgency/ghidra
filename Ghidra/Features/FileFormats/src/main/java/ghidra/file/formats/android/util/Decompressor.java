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
package ghidra.file.formats.android.util;

import java.io.*;

import org.apache.commons.compress.compressors.lz4.BlockLZ4CompressorInputStream;

import ghidra.file.formats.android.art.ArtStorageMode;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class Decompressor {

	/**
	 * Decompresses the source bytes using the specified "mode".
	 * @param mode storage mode (aka compression type)
	 * @param source compressed bytes, if compressed
	 * @param maxDecompressedSize maximum byte size after being decompressed
	 * @return decompressed bytes
	 * @param monitor task monitor for controlling the task
	 * @throws IOException should an error occur reading the bytes
	 */
	public static byte[] decompress(ArtStorageMode mode, byte[] source, int maxDecompressedSize,
			TaskMonitor monitor) throws IOException {
		if (mode == ArtStorageMode.kStorageModeLZ4) {
			return decompressLZ4(source, maxDecompressedSize, monitor);
		}
		if (mode == ArtStorageMode.kStorageModeLZ4HC) {
			return decompressLZ4HC(source, maxDecompressedSize, monitor);
		}
		if (mode == ArtStorageMode.kStorageModeUncompressed) {
			return source;//not compressed
		}
		throw new IOException("invalid storage mode");
	}

	/**
	 *  Call the LZ4 decompression library 
	 */
	private static byte[] decompressLZ4(byte[] source, int maxDecompressedSize, TaskMonitor monitor)
			throws IOException {
		try {
			ByteArrayOutputStream decompressedStream = new ByteArrayOutputStream();
			BlockLZ4CompressorInputStream compressedStream =
				new BlockLZ4CompressorInputStream(new ByteArrayInputStream(source));
			FileUtilities.copyStreamToStream(compressedStream, decompressedStream, monitor);
			return decompressedStream.toByteArray();
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}

	/**
	 *  Call the LZ4-HC decompression library 
	 */
	private static byte[] decompressLZ4HC(byte[] source, int maxDecompressedSize,
			TaskMonitor monitor) throws IOException {
		try {
			ByteArrayOutputStream decompressedStream = new ByteArrayOutputStream();
			BlockLZ4CompressorInputStream compressedStream =
				new BlockLZ4CompressorInputStream(new ByteArrayInputStream(source));
			FileUtilities.copyStreamToStream(compressedStream, decompressedStream, monitor);
			return decompressedStream.toByteArray();
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}
}
