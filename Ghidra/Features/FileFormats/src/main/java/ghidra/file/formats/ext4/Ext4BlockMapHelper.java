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
package ghidra.file.formats.ext4;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.formats.gfilesystem.FSRL;

/**
 * Helper class that handles the blockmap data stored in an inode's i_block[] array
 */
public class Ext4BlockMapHelper {
	private static final int INDIRECT_BLOCK_INDEX = 12;
	private static final int DOUBLE_INDIRECT_BLOCK_INDEX = 13;
	private static final int TRIPLE_INDIRECT_BLOCK_INDEX = 14;
	private static final int INODE_BLOCKMAP_COUNT = 15;

	/**
	 * Creates a {@link RangeMappedByteProvider} from the old-style block map data found in the
	 * inode's i_block field.
	 *   
	 * @param rawIBlockBytes raw bytes from the inode's i_block
	 * @param provider the file system volume provider
	 * @param expectedLength the length the file should be (from the inode)
	 * @param blockSize file system blockSize 
	 * @param fsrl {@link FSRL} to assign to the new ByteProvider
	 * @return new {@link ByteProvider} containing the blocks of the volume that were specified
	 * by the blockmap data
	 * @throws IOException if error
	 */
	public static ByteProvider getByteProvider(byte[] rawIBlockBytes, ByteProvider provider,
			long expectedLength, int blockSize, FSRL fsrl) throws IOException {
		BinaryReader iBlockReader =
			new BinaryReader(new ByteArrayProvider(rawIBlockBytes), true /* LE */);
		int[] blockNumbers = iBlockReader.readNextIntArray(INODE_BLOCKMAP_COUNT);

		RangeMappedByteProvider bp = new RangeMappedByteProvider(provider, fsrl);

		// the location of the first 12 blocks of the file are held in [0..11] 
		addFromArray(blockNumbers, 0, INDIRECT_BLOCK_INDEX, 0, bp, blockSize, expectedLength,
			provider);

		// the location of the next blockSize/4 (ie. 4096/4=1024) blocks of the file are
		// held in an array that is located in the block pointed to by [12]
		addFromArray(blockNumbers, INDIRECT_BLOCK_INDEX, DOUBLE_INDIRECT_BLOCK_INDEX, 1, bp,
			blockSize, expectedLength, provider);

		// the location of the next blocks of the file are held in an array that is 
		// double-ly indirectly pointed to by [13]
		addFromArray(blockNumbers, DOUBLE_INDIRECT_BLOCK_INDEX, TRIPLE_INDIRECT_BLOCK_INDEX, 2, bp,
			blockSize, expectedLength, provider);

		// the location of the next blocks of the file are held in an array that is 
		// triply indirectly pointed to by [14]
		addFromArray(blockNumbers, TRIPLE_INDIRECT_BLOCK_INDEX, INODE_BLOCKMAP_COUNT, 3, bp,
			blockSize, expectedLength, provider);

		return bp;
	}

	private static void addFromArray(int[] blockNums, int start, int end, int indirectLevel,
			RangeMappedByteProvider ebp, int blockSize, long expectedLength, ByteProvider provider)
			throws IOException {
		BinaryReader reader = new BinaryReader(provider, true /* LE */ );
		for (int i = start; i < end && ebp.length() < expectedLength; i++) {
			if ( indirectLevel > 0 ) {
				int[] subBlockNumbers = reader.readIntArray(blockNums[i] * blockSize,
					blockSize / BinaryReader.SIZEOF_INT);
				addFromArray(subBlockNumbers, 0, subBlockNumbers.length, indirectLevel - 1, ebp,
					blockSize, expectedLength, provider);
			}
			else {
				int bytesFromBlock = (int) Math.min(blockSize, expectedLength - ebp.length());
				long blockNum = Integer.toUnsignedLong(blockNums[i]);
				ebp.addRange(blockNum == 0 ? -1 : blockNum * blockSize, bytesFromBlock);
			}
		}
	}
}
