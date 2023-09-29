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
import java.util.*;

import org.apache.commons.lang3.ArrayUtils;

import ghidra.app.util.bin.ByteProvider;
import ghidra.file.formats.zlib.ZLIB;

public class CramFsInputStream extends InputStream {
	private CramFsInode iNode;
	private List<Integer> blockPointerList = new ArrayList<>();
	private List<CramFsBlock> blockList;
	private List<ByteArrayOutputStream> decompressedBlockStreams = new ArrayList<>();
	private List<Byte> decompressedOutputList = new ArrayList<>();
	private ZLIB zlib = new ZLIB();
	private ByteProvider byteProvider;
	private CramFsBlockReader cramfsBlockReader;
	private int defaultBlockSize;
	private int currentByte = 0;
	private boolean blockExtensionEnabled;

	/**
	 * Constructor for cramfs input stream.
	 * @param byteProvider the underlined byte provider for the input stream.
	 * @param iNode the parent node for the input stream.
	 * @param blockExtensionEnabled the enabled block extensions for the input stream.
	 * @throws IOException if there is an error when creating the input stream.
	 */
	public CramFsInputStream(ByteProvider byteProvider, CramFsInode iNode,
			boolean blockExtensionEnabled) throws IOException {
		this.iNode = iNode;
		this.byteProvider = byteProvider;
		this.blockExtensionEnabled = blockExtensionEnabled;
		defaultBlockSize = CramFsConstants.DEFAULT_BLOCK_SIZE;
		blockList = getDataBlocks();
		decompressAllBlocks();
		combineDecompressedBlockStreams();
	}

	/**
	 * Sends the inode to the CramFs block factory and gets back a list of 
	 * CramFs blocks for the data associated with the inode.
	 * @return a list of cramFs blocks to be used for decompression.
	 */
	private List<CramFsBlock> getDataBlocks() {
		CramFsBlockFactory blockFactory =
			new CramFsBlockFactory(iNode, byteProvider, blockPointerList, blockExtensionEnabled);
		return blockFactory.produceBlocks();
	}

	/**
	 * Gets the Cram file system block list.
	 * @return the block list
	 */
	public List<CramFsBlock> getBlockList() {
		return blockList;
	}

	/**
	 * Decompress all the data blocks that an inode points to. 
	 * Adds the uncompressed blocks to an internal list for later processing.
	 * @throws IOException if there is an error when decompressing the data blocks.
	 */
	private void decompressAllBlocks() throws IOException {
		for (int i = 0; i < cramfsBlockReader.getNumBlockPointers() - 1; i++) {
			InputStream compressedIn = new ByteArrayInputStream(cramfsBlockReader.readDataBlock(i));
			decompressedBlockStreams
					.add(zlib.decompress(compressedIn, CramFsConstants.DEFAULT_BLOCK_SIZE));
		}
	}

	/**
	 * Combines all the ZLIB decompressed block stream bytes into one list.
	 */
	private void combineDecompressedBlockStreams() {
		for (int i = 0; i < decompressedBlockStreams.size(); i++) {
			byte[] bytes = decompressedBlockStreams.get(i).toByteArray();
			List<Byte> bytesList = Arrays.asList(ArrayUtils.toObject(bytes));
			decompressedOutputList.addAll(bytesList);
		}
	}

	/**
	 * Decompress the specified block.
	 * @param blockIndex the block to decompress.
	 * @return decompressed output stream.
	 * @throws IOException if zlib decompress fails.
	 */
	public ByteArrayOutputStream decompressBlock(int blockIndex) throws IOException {
		InputStream compressedIn = new ByteArrayInputStream(blockList.get(blockIndex).readBlock());
		return zlib.decompress(compressedIn, defaultBlockSize);

	}

	/**
	 * Reads one byte from the internal uncompressed output list of Bytes.
	 * @return The byte value from the internal list at the current read position.
	 * @throws IOException if there is an error while reading. 
	 */
	@Override
	public int read() throws IOException {
		if (currentByte < decompressedOutputList.size()) {
			byte readByte = decompressedOutputList.get(currentByte).byteValue();
			currentByte++;
			return Byte.toUnsignedInt(readByte);
		}
		return -1;
	}

}
