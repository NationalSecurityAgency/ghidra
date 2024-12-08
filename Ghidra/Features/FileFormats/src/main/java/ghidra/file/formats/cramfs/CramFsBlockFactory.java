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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;

public class CramFsBlockFactory {
	static final int IS_DIRECT_POINTER = (1 << 30);
	static final int IS_UNCOMPRESSED = (1 << 31);

	private CramFsInode cramfsInode;
	private ByteProvider provider;
	private List<Integer> blockPointerList;
	//For the size of compressed block sizes.
	private List<Integer> blockSizes;
	//It is possible this will always default to false, but just in case. 
	//This will determine if the data blocks have special conditions on them.
	private boolean blockPointerExtensionsEnabled;

	/**
	 * This class takes an iNode and produces a List of CramFsBlocks that are 
	 * set appropriately depending on their flags, 
	 * and the flag CRAMFS_FLAG_EXT_BLOCK_POINTERS from the CramFsSuper block.
	 * @param cramfsInode the parent node for this block.
	 * @param provider the byteProvider for the block header.
	 * @param blockPointerList a list of the block pointers. 
	 * @param blockPointerExtensionsEnabled true if the block pointer extensions are enabled.
	 */
	public CramFsBlockFactory(CramFsInode cramfsInode, ByteProvider provider,
			List<Integer> blockPointerList, boolean blockPointerExtensionsEnabled) {
		this.cramfsInode = cramfsInode;
		this.provider = provider;
		this.blockPointerExtensionsEnabled = blockPointerExtensionsEnabled;
		this.blockPointerList = blockPointerList;
	}

	/**
	 * This function will use the inode to calculate certain things for the block,
	 * such as calculating compressed block sizes etc.
	 * If the block pointer extension flag is set not in the super block,
	 * we will calculate the size of each zlibbed block, and create a list of blocks appropriately.
	 * @return the block list.
	 */
	public List<CramFsBlock> produceBlocks() {

		List<CramFsBlock> blockList = new ArrayList<>();

		if (!blockPointerExtensionsEnabled) { //focus on this one
			blockSizes = calculateCompressedBlockSizes();
			//Use blockSizes to create Blocks.
			for (int i = 0; i < blockSizes.size(); i++) {
				blockList.add(new CramFsBlock(blockPointerList.get(i), blockSizes.get(i).intValue(),
					provider));
			}
		}

		return blockList;
	}

	/**
	 * Returns the cramfsInode.
	 * @return the cramfsInode.
	 */
	public CramFsInode getCramfsInode() {
		return cramfsInode;
	}

	private List<Integer> calculateCompressedBlockSizes() {
		List<Integer> compressedBlockSizes = new ArrayList<Integer>();

		for (int i = 0; i < blockPointerList.size() - 1; i++) {
			compressedBlockSizes.add(blockPointerList.get(i + 1) - blockPointerList.get(i));
		}

		return compressedBlockSizes;
	}

}
