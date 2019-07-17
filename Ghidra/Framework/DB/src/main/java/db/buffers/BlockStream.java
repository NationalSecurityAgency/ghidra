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

import java.io.Closeable;

/**
 * <code>BlockStream</code> provides a BufferFile block stream.
 */
public interface BlockStream extends Closeable {
	
	/**
	 * Get the raw block size
	 * @return block size
	 */
	int getBlockSize();
	
	/**
	 * Get the number of blocks to be transferred
	 * @return block count
	 */
	int getBlockCount();

}
