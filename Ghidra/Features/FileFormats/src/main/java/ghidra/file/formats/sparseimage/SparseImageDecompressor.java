/* ###
 * IP: Apache License 2.0
 * NOTE: Based on the simg2img code from The Android Open Source Project
 */
/*
 * Copyright (C) 2012 The Android Open Source Project
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

package ghidra.file.formats.sparseimage;

import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.CRC32;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Decodes / decompresses a sparse image file into a supplied {@link OutputStream}.
 * <p>
 * Code extracted from SparseImageFileSystem, which mentioned the simg2img code
 * from The Android Open Source Project.
 */
public class SparseImageDecompressor {

	private BinaryReader reader;
	private CRC32 crc;
	private int bufferSize = 1024 * 1024;
	private OutputStream tempFos;
	private int blockSize;

	/**
	 * Creates a new sparse image decompressor, which will read from the specified {@link ByteProvider}
	 * and write to the specified {@link OutputStream}.
	 *
	 * @param provider {@link ByteProvider} to read from.
	 * @param os {@link OutputStream} to write to.
	 */
	public SparseImageDecompressor(ByteProvider provider, OutputStream os) {
		this.reader = new BinaryReader(provider, true);
		this.crc = new CRC32();
		this.tempFos = os;
	}

	/**
	 * Performs the decompression of the file, writing all bytes available to the
	 * output stream.
	 *
	 * @param monitor {@link TaskMonitor} to watch for cancel and to update with progress info.
	 * @throws CancelledException if user cancels
	 * @throws IOException if error when reading or writing.
	 */
	public void decompress(TaskMonitor monitor) throws CancelledException, IOException {

		SparseHeader sparseHeader = new SparseHeader(reader);
		if (sparseHeader.getMajor_version() != SparseConstants.MAJOR_VERSION_NUMBER) {
			throw new IOException("Unsupported major version number.");
		}

		this.blockSize = sparseHeader.getBlk_sz();

		int totalBlocks = 0;
		monitor.setMaximum(sparseHeader.getTotal_chunks());
		monitor.setProgress(0);

		for (int i = 0; i < sparseHeader.getTotal_chunks(); i++) {
			monitor.checkCanceled();
			monitor.setMessage(
				"Processing chunk " + i + " of " + sparseHeader.getTotal_chunks() + "...");

			ChunkHeader chunkHeader = new ChunkHeader(reader);
			short chunkType = chunkHeader.getChunk_type();
			int chunkSize = chunkHeader.getChunk_sz();
			if (chunkType == SparseConstants.CHUNK_TYPE_RAW) {
				processRawChunk(chunkSize, monitor);
				totalBlocks += chunkSize;
			}
			else if (chunkType == SparseConstants.CHUNK_TYPE_FILL) {
				processFillChunk(chunkSize, monitor);
				totalBlocks += chunkSize;
			}
			else if (chunkType == SparseConstants.CHUNK_TYPE_DONT_CARE) {
				processSkipChunk(chunkSize, monitor);
				totalBlocks += chunkSize;
			}
			else if (chunkType == SparseConstants.CHUNK_TYPE_CRC32) {
				processCrcChunk();
				totalBlocks += chunkSize;
			}
			else {
				throw new IOException("Unkown chunk type: " + chunkType);
			}
			monitor.incrementProgress(1);
		}

		long totalSize = (long) totalBlocks * sparseHeader.getBlk_sz();
		monitor.setMessage("Total bytes: " + totalSize);
	}

	/**
	 * Processes an embedded crc checkvalue, throwing an exception of the current crc
	 * does not match the stored crc.
	 * <p>
	 * @throws IOException if crc bad
	 */
	private void processCrcChunk() throws IOException {
		int fileCrc = reader.readNextInt();
		int value = (int) crc.getValue();
		if (fileCrc != value) {
			throw new IOException("Computed crc (0x" + Integer.toHexString(value) +
				") did not match the expected crc (0x" + Integer.toHexString(fileCrc) + ").");
		}
	}

	/**
	 * Writes a chunk of blocks are are zero filled.
	 * <p>
	 * @param blocks number of blocks to write
	 * @param monitor {@link TaskMonitor} to watch
	 * @throws IOException if error writing
	 * @throws CancelledException if user cancels
	 */
	private void processSkipChunk(int blocks, TaskMonitor monitor)
			throws IOException, CancelledException {
		long length = (long) blocks * blockSize;
		if (length > bufferSize) {
			byte[] bytes = new byte[bufferSize];
			for (int i = 0; i < length / bufferSize; i++) {
				monitor.checkCanceled();
				tempFos.write(bytes);
			}
		}
		int size = (int) length % bufferSize;
		byte[] bytes = new byte[size];
		tempFos.write(bytes);
	}

	/**
	 * Fill an array with a repeated pattern of bytes.
	 * <p>
	 * The values in srcPattern are copied into destArray, repeating from the beginning
	 * of srcPattern as many times as necessary to fill destArray.
	 * <p>
	 * @param srcPattern byte array with source pattern
	 * @param destArray byte array destination
	 */
	private static void fillArray(byte[] srcPattern, byte[] destArray) {
		for (int srcIndex = 0, destIndex =
			0; destIndex < destArray.length; srcIndex++, destIndex++) {
			if (srcIndex >= srcPattern.length) {
				srcIndex = 0;
			}
			destArray[destIndex] = srcPattern[srcIndex];
		}
	}

	/**
	 * Writes a chunk of blocks that are defined by a repeated pattern of 4 bytes.
	 * <p>
	 * @param blocks number of blocks to write
	 * @param monitor {@link TaskMonitor} to monitor
	 * @throws IOException if error when writing or reading
	 * @throws CancelledException if user cancels
	 */
	private void processFillChunk(int blocks, TaskMonitor monitor)
			throws IOException, CancelledException {

		int fillInt = reader.readNextInt();

		long length = (long) blocks * blockSize;
		int fillBufferSize = (int) Math.min(length, bufferSize);
		byte[] fillBuffer = new byte[fillBufferSize];

		byte[] srcPattern = { (byte) (fillInt >> 24), (byte) (fillInt >> 16), (byte) (fillInt >> 8),
			(byte) (fillInt & 0xff) };
		fillArray(srcPattern, fillBuffer);

		while (length > 0) {
			monitor.checkCanceled();
			int bytesToWrite = (int) Math.min(length, fillBufferSize);
			crc.update(fillBuffer, 0, bytesToWrite);
			tempFos.write(fillBuffer, 0, bytesToWrite);
			length -= bytesToWrite;
		}
	}

	/**
	 * Writes a chunk of blocks are are read from the source file.
	 * <p>
	 * @param blocks number of blocks to copy
	 * @param monitor {@link TaskMonitor} to monitor
	 * @throws IOException if error when reading or writing
	 * @throws CancelledException if user cancels
	 */
	private void processRawChunk(int blocks, TaskMonitor monitor)
			throws IOException, CancelledException {
		long length = (long) blocks * blockSize;
		while (length > 0) {
			monitor.checkCanceled();
			int bytesToRead = (int) Math.min(length, bufferSize);
			byte[] bytes = reader.readNextByteArray(bytesToRead);
			crc.update(bytes);
			tempFos.write(bytes);
			length = length - bytesToRead;
		}
	}
}
