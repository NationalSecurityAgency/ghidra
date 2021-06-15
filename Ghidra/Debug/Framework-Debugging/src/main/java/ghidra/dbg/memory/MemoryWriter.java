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
package ghidra.dbg.memory;

import java.util.concurrent.CompletableFuture;

/**
 * The functional interface for writes to a cached memory
 * 
 * @see CachedMemory
 */
public interface MemoryWriter {
	/**
	 * Write target memory
	 * 
	 * If cached, the given write command is immediately forwarded to the wrapped write, and the
	 * cache is updated so that subsequent reads within the same region do not get forwarded.
	 */
	// TODO: Use ByteBuffer instead?
	public CompletableFuture<Void> writeMemory(long address, byte[] data);
}
