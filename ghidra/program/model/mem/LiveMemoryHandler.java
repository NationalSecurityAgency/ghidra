/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.model.mem;

import ghidra.program.model.address.Address;

/**
 * Live memory handler interface.
 */
public interface LiveMemoryHandler {

	/**
	 * Called when the memory map is re-initializing. Usually after an undo or redo.
	 */
	public void clearCache();

	/**
	 * Gets the byte at the given address.
	 * @param addr the address of the byte to be retrieved
	 * @return the byte at the given address.
	 * @throws MemoryAccessException if the byte can't be read.
	 */
	public byte getByte(Address addr) throws MemoryAccessException;
	
	/**
	 * Get the bytes at the given address and size and put them into the destination buffer.
	 * @param address the address of the first byte to be retrieved.
	 * @param buffer the byte buffer in which to place the bytes.
	 * @param startIndex the starting index in the buffer to put the first byte.
	 * @param size the number of bytes to retrieve and put in the buffer.
	 * @return the number of bytes placed into the given buffer.
	 * @throws MemoryAccessException if the bytes can't be read.
	 */
	public int getBytes(Address address, byte[] buffer, int startIndex, int size) throws MemoryAccessException;

	/**
	 * Writes the given byte value to the address in memory.
	 * @param address the address whose byte is to be updated to the new value.
	 * @param value the value to set at the given address.
	 * @throws MemoryAccessException if the value can not be written to the memory.
	 */
	public void putByte(Address address, byte value) throws MemoryAccessException;
	
	/**
	 * Writes the given bytes to memory starting at the given address.
	 * @param address the address in memory to write the bytes.
	 * @param source the buffer containing the byte values to be written to memory.
	 * @param startIndex the starting index in the buffer to get byte values.
	 * @param size the number of bytes to write to memory.
	 * @return the number of bytes written to memory.
	 * @throws MemoryAccessException if the bytes can't be written to memory.
	 */
	public int putBytes(Address address, byte[] source, int startIndex, int size) throws MemoryAccessException;

	/**
	 * Adds a LiveMemoryListener to this handler.  The listener will be notified when memory
	 * bytes change.
	 * @param listener the listener to be notified of memory byte value changes.
	 */
	public void addLiveMemoryListener(LiveMemoryListener listener);
	
	/**
	 * Removes the LiveMemoryListener from this handler.
	 * @param listener the listener to be removed.
	 */
	public void removeLiveMemoryListener(LiveMemoryListener listener);
}
