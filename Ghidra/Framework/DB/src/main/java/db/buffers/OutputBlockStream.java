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
 * <code>OutputBlockStream</code> provides a BufferFile output block stream.
 * The nature of the stream and the block sequence is determined by the
 * particular instance.
 */
public interface OutputBlockStream extends BlockStream {

	/**
	 * Write the specified block to the corresponding BufferFile.
	 * @param block a BufferFile block which corresponds to a specific block index
	 * @throws IOException if an unexpected error occurs while 
	 * writing the block
	 */
	void writeBlock(BufferFileBlock block) throws IOException;
	
}
