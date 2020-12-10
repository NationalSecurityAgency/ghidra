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
package agent.dbgeng.manager;

import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

import com.google.common.collect.RangeSet;

public interface DbgMemoryOperations {

	/**
	 * Read memory
	 * 
	 * @param addr the address to begin reading at
	 * @param buf the buffer to read into
	 * @param len the length of data to read
	 * @return a future which completes giving the ranges successfully read
	 */
	CompletableFuture<RangeSet<Long>> readMemory(long addr, ByteBuffer buf, int len);

	/**
	 * Read memory
	 * 
	 * The length is determined by the available space in the destination buffer
	 * 
	 * @param addr the address to begin reading at
	 * @param buf the buffer to read into
	 * @return a future which completes giving the ranges successfully read
	 */
	default CompletableFuture<RangeSet<Long>> readMemory(long addr, ByteBuffer buf) {
		return readMemory(addr, buf, buf.remaining());
	}

	/**
	 * Write memory
	 * 
	 * @param addr the address to begin writing at
	 * @param buf the buffer to copy from
	 * @param len the length of data to write
	 * @return a future that completes when the write succeeds in its entirety
	 */
	CompletableFuture<Void> writeMemory(long addr, ByteBuffer buf, int len);

	/**
	 * Write memory
	 * 
	 * The length is determined by the available data in the source buffer
	 * 
	 * @param addr the address to begin writing at
	 * @param buf the buffer to copy from
	 * @return a future that completes when the write succeeds in its entirety
	 */
	default CompletableFuture<Void> writeMemory(long addr, ByteBuffer buf) {
		return writeMemory(addr, buf, buf.remaining());
	}
}
