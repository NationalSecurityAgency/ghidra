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
package db.buffers;

import ghidra.util.BigEndianDataConverter;

/**
 * <code>BufferFileBlock</code> is used to hold BufferFile blocks 
 * for use during block streaming operations.
 * <p>  
 * Block indexes are absolute where 0 corresponds
 * to the head block in the BufferFile.  It is important to note that 
 * this number is off by 1 from DataBuffer numbering and the index values
 * utilized by {@link BufferFile#getIndexCount()}, {@link BufferFile#get(DataBuffer, int)},
 * {@link BufferFile#put(DataBuffer, int)}, etc..  It is important for
 * each implementation to normalize to absolute block indexes.
 */
public class BufferFileBlock {

	private int blockIndex;
	private byte[] buffer;

	/**
	 * BufferFileBlock constructor
	 * @param blockIndex block index
	 * @param buffer block buffer (size must match block-size for associated buffer file)
	 */
	public BufferFileBlock(int blockIndex, byte[] buffer) {
		this.blockIndex = blockIndex;
		this.buffer = buffer;
	}

	/**
	 * BufferFileBlock constructor for use when reconstructing instance
	 * from block stream
	 * @param bytes buffer data received from block stream.  Buffer index will be
	 * determined by first 4-bytes contained within the bytes array (big-endian).
	 */
	public BufferFileBlock(byte[] bytes) {
		blockIndex = BigEndianDataConverter.INSTANCE.getInt(bytes, 0);
		buffer = new byte[bytes.length - 4];
		System.arraycopy(bytes, 4, buffer, 0, buffer.length);
	}

	/**
	 * Get block size
	 * @return block size
	 */
	public int size() {
		return buffer.length;
	}

	/**
	 * Get absolute block index, where 0 corresponds to the first 
	 * physical block within the buffer file.
	 * @return block index
	 */
	public int getIndex() {
		return blockIndex;
	}

	/**
	 * Get block data buffer
	 * @return block data buffer
	 */
	public byte[] getData() {
		return buffer;
	}

	/**
	 * Get block as byte array suitable for use in block stream and
	 * reconstruction.
	 * @return block as byte array
	 */
	public byte[] toBytes() {
		byte[] bytes = new byte[buffer.length + 4];
		System.arraycopy(buffer, 0, bytes, 4, buffer.length);
		BigEndianDataConverter.INSTANCE.putInt(bytes, 0, blockIndex);
		return bytes;
	}

}
