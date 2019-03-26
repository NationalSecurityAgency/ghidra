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

import java.io.IOException;

/**
 * <code>InputBlockStream</code> provides a BufferFile input block stream.
 * The nature of the stream and the block sequence is determined by the
 * particular instance.
 */
public interface InputBlockStream extends BlockStream {

	/**
	 * Read next block from stream
	 * @return a BufferFile block which corresponds to a specific block index
	 * or null if no more blocks available
	 * @throws IOException if an unexpected error occurs while 
	 * reading the file
	 */
	BufferFileBlock readBlock() throws IOException;

	/**
	 * Get the total number of blocks to be transfered.
	 * @return total block count
	 */
	@Override
	int getBlockCount();

	/**
	 * Determine if header block included in stream.  Some stream implementations
	 * do not include or don't have access to the buffer file header block and may 
	 * be excluded.  If header is required, it will need to be reconstructed by
	 * setting the free index list and all buffer file parameters.
	 * @return true if header block #0 included in stream, else false
	 */
	boolean includesHeaderBlock();

}
