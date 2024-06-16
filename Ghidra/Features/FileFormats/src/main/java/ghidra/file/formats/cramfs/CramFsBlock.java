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

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;

/**
 * @see <a href="https://github.com/torvalds/linux/tree/master/fs/cramfs">/fs/cramfs</a>
 */
public class CramFsBlock {
	private int blockPointer;
	private int startAddress;
	private boolean isDirectPointer;
	private boolean isCompressed;
	private int blockSize;
	private ByteProvider provider;

	static final int IS_DIRECT_POINTER = (1 << 30);
	static final int IS_UNCOMPRESSED = (1 << 31);

	/**
	 * This constructor is for regular contiguous blocks in a cramfs file
	 * that do not have the extension flag set.
	 * @param start the address for the start of this block.
	 * @param blockSize the size of the cramfs block.
	 * @param provider the byteProvider for the block header.
	 */
	public CramFsBlock(int start, int blockSize, ByteProvider provider) {
		startAddress = blockPointer = start;
		this.blockSize = blockSize;
		this.provider = provider;
		isDirectPointer = false;
		isCompressed = false;
	}

	/**
	 * Returns the block pointer for the cramfs block.
	 * @return the block pointer for the cramfs block.
	 */
	public int getBlockPointer() {
		return blockPointer;
	}

	/**
	 * Returns true if the block is a direct pointer.
	 * @return true if the block is a direct pointer.
	 */
	public boolean isDirectPointer() {
		return isDirectPointer;
	}

	/**
	 * Returns true if the block is compressed.
	 * @return true if the block is compressed.
	 */
	public boolean isCompressed() {
		return isCompressed;
	}

	/**
	 * Returns the size of the cramfs block. 
	 * @return the size of the cramfs block. 
	 */
	public int getBlockSize() {
		return blockSize;
	}

	/**
	 * Reads the data block in its entirety.
	 * @return the read bytes in a byte array.
	 * @throws IOException if there is an error while reading the data block.
	 */
	public byte[] readBlock() throws IOException {
		return provider.readBytes(startAddress, blockSize);
	}

}
