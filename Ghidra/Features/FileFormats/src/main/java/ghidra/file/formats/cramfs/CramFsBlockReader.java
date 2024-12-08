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
package ghidra.file.formats.cramfs;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.file.formats.zlib.ZLIB;

public class CramFsBlockReader {

	private ByteProvider provider;
	private CramFsInode cramfsInode;
	private List<Integer> blockPointerTable = new LinkedList<>();
	private List<Integer> compressedBlockSizes = new ArrayList<>();
	private boolean isLittleEndian;

	/**
	 * This constructor reads the CramFS Block.
	 * @param provider the byteProvider for the block header.
	 * @param cramfsInode the parent node for this block.
	 * @param isLittleEndian if the block is little endian or not.
	 * @throws IOException if there is an error while reading the block.
	 */
	public CramFsBlockReader(ByteProvider provider, CramFsInode cramfsInode, boolean isLittleEndian)
			throws IOException {
		this.provider = provider;
		this.cramfsInode = cramfsInode;
		this.isLittleEndian = isLittleEndian;
		populateBlockPointerTable();
		calculateCompressedBlockSizes();
	}

	private void populateBlockPointerTable() throws IOException {

		int numBlockPointers = calculateStartAddress();

		if (numBlockPointers < 0) {
			throw new IOException("Start Address for data block not found");
		}

		int inodeDataOffset = cramfsInode.getOffsetAdjusted();
		for (int i = 0; i < numBlockPointers - 1; i++) {

			byte[] tempBuffer =
				provider.readBytes(inodeDataOffset, CramFsConstants.BLOCK_POINTER_SIZE);
			//byteProvider will be Big Endian by default
			ByteBuffer byteBuffer = ByteBuffer.wrap(tempBuffer);
			if (isLittleEndian) {
				blockPointerTable.add(Integer.reverseBytes(byteBuffer.getInt()));
			}
			else {
				blockPointerTable.add(byteBuffer.getInt());
			}

			inodeDataOffset += CramFsConstants.BLOCK_POINTER_SIZE;
		}
	}

	/**
	 * Calculates the start address of the data block using the 
	 * block pointer table that precedes compressed data.
	 * @return the number of block pointers associated with this data section.
	 * @throws IOException if error occurs reading from the byte provider.
	 */
	private int calculateStartAddress() throws IOException {
		int numBlockPointers = -1;
		int dataOffset = cramfsInode.getOffsetAdjusted();
		int dataOffsetStart = dataOffset;
		boolean firstAddressFound = false;

		while (!firstAddressFound) {
			byte[] possibleZlibHeader =
				provider.readBytes(dataOffset, CramFsConstants.ZLIB_MAGIC_SIZE);
			if (Arrays.equals(possibleZlibHeader, ZLIB.ZLIB_COMPRESSION_DEFAULT) ||
				Arrays.equals(possibleZlibHeader, ZLIB.ZLIB_COMPRESSION_BEST) ||
				Arrays.equals(possibleZlibHeader, ZLIB.ZLIB_COMPRESSION_NO_LOW)) {
				blockPointerTable.add(dataOffset);
				firstAddressFound = true;
				return ((dataOffset - dataOffsetStart) / CramFsConstants.BLOCK_POINTER_SIZE) + 1;
			}
			dataOffset += 4;
		}
		return numBlockPointers;
	}

	/**
	 * Uses the block pointer table which contains addresses
	 * to calculate the size of the compressed blocks of data
	 * for use in uncompressing each block. Adds the size of each block
	 * to the compressedBlockSizes arrayList.
	 */
	private void calculateCompressedBlockSizes() {

		for (int i = 0; i < blockPointerTable.size() - 1; i++) {
			compressedBlockSizes.add(blockPointerTable.get(i + 1) - blockPointerTable.get(i));
		}

	}

	/**
	 * Reads one block from the data pointed to by the CramfsInode.
	 * @param dataBlockIndex the index of the block to read.
	 * @return a byte array representing the compressed data for a compressed block.
	 * @throws IOException if error occurs when reading the data block.
	 */
	public byte[] readDataBlock(int dataBlockIndex) throws IOException {
		return provider.readBytes(blockPointerTable.get(dataBlockIndex),
			compressedBlockSizes.get(dataBlockIndex));
	}

	/**
	 * Sends compressed data block to be uncompressed.
	 * @param dataBlockIndex the index of the block to read.
	 * @return Uncompressed data as a ByteArrayInputStream.
	 * @throws IOException if an error occurs when reading the decompressed data block.
	 */
	public InputStream readDataBlockDecompressed(int dataBlockIndex) throws IOException {
		Integer index = blockPointerTable.get(dataBlockIndex);
		Integer length = compressedBlockSizes.get(dataBlockIndex);
		byte[] compressedBytes = provider.readBytes(index, length);
		InputStream compressedInputStream = new ByteArrayInputStream(compressedBytes);
		ZLIB zlib = new ZLIB();

		ByteArrayOutputStream decompressedOutputStream =
			zlib.decompress(compressedInputStream, CramFsConstants.DEFAULT_BLOCK_SIZE);
		return new ByteArrayInputStream(decompressedOutputStream.toByteArray());
	}

	/**
	 * Gets the provider.
	 * @return provider.
	 */
	public ByteProvider getProvider() {
		return provider;
	}

	/**
	 * Gets the CramfsInode.
	 * @return cramfsInode.
	 */
	public CramFsInode getCramfsInode() {
		return cramfsInode;
	}

	/**
	 * Gets the block pointer table.
	 * @return the block pointer table.
	 */
	public List<Integer> getBlockPointerTable() {
		return blockPointerTable;
	}

	/**
	 * Gets the number of block pointers.
	 * @return the number of block pointers.
	 */
	public int getNumBlockPointers() {
		return blockPointerTable.size() - 1;
	}

}
