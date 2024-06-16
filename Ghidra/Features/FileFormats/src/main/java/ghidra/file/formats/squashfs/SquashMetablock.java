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

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class SquashMetablock {

	// Header for the metablock which contains two fields:
	// isCompressed - If the 1 << 15 bit is cleared, the metablock is compressed
	// fragmentSize   - The size of the metablock in bytes (lower 15 bits)
	private final short header;

	/**
	 * Represents the metadata proceeding a data block within the SquashFS archive
	 * @param reader A binary reader with pointer index at the start of the metadata
	 * @throws IOException Any read operation failure
	 */
	public SquashMetablock(BinaryReader reader) throws IOException {

		// The metadata short contains both size and compression info to be masked out
		header = reader.readNextShort();

	}

	public boolean isCompressed() {
		return (header & SquashConstants.METABLOCK_UNCOMPRESSED_MASK) == 0;
	}

	public short getBlockSize() {

		short blockSize = (short) (header & ~SquashConstants.METABLOCK_UNCOMPRESSED_MASK);

		// Let the user know if the current block size exceeds what is allowed per standard
		if (blockSize > SquashConstants.MAX_UNIT_BLOCK_SIZE) {
			Msg.warn(this, "Unit block size is too large!");
		}

		return blockSize;
	}

}
