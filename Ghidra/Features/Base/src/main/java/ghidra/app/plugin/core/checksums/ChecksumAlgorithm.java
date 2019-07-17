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
package ghidra.app.plugin.core.checksums;

import java.nio.ByteBuffer;

import org.apache.commons.lang3.ArrayUtils;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.NumericUtilities;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This abstract class is used for the computation and formatting of various checksum algorithms.
 */
public abstract class ChecksumAlgorithm implements ExtensionPoint {

	protected String name;
	protected byte[] checksum;

	/**
	 * Constructs a new checksum algorithm with the given name.
	 * 
	 * @param name The name of the checksum algorithm.
	 */
	public ChecksumAlgorithm(String name) {
		this.name = name;
	}

	/**
	 * Gets the name of the checksum algorithm.
	 * 
	 * @return The name of the checksum algorithm.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Gets the last computed checksum.
	 * 
	 * @return The last computed checksum, or null if the checksum has never been generated.
	 */
	public byte[] getChecksum() {
		return checksum;
	}

	/**
	 * Updates (or generates) the checksum for this algorithm over the given address range.
	 * 
	 * @param memory The memory over which to generate the checksum.
	 * @param addrSet The addresses over which to generate the checksum.
	 * @param monitor Cancelable task monitor.
	 * @param provider An optional checksum provider that has options used for generating the
	 *   checksum.  Could be null.
	 * @throws MemoryAccessException If there was a problem accessing the specified memory.
	 * @throws CancelledException If checksum generation was cancelled.
	 */
	public abstract void updateChecksum(Memory memory, AddressSetView addrSet, TaskMonitor monitor,
			ComputeChecksumsProvider provider) throws MemoryAccessException, CancelledException;

	/**
	 * Updates (or generates) the checksum for this algorithm over the given address range.
	 * 
	 * @param memory The memory over which to generate the checksum.
	 * @param addrSet The addresses over which to generate the checksum.
	 * @param monitor Cancelable task monitor.
	 * @throws MemoryAccessException If there was a problem accessing the specified memory.
	 * @throws CancelledException If checksum generation was cancelled.
	 */
	final public void updateChecksum(Memory memory, AddressSetView addrSet, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {
		updateChecksum(memory, addrSet, monitor, null);
	}

	/**
	 * Checks whether or not this algorithm supports showing its result in decimal format.
	 * 
	 * @return True if this algorithm supports showing its result in decimal format; otherwise, false.
	 */
	public boolean supportsDecimal() {
		return false;
	}

	/**
	 * Converts a long to a little-endian array.
	 * 
	 * @param l The long to convert.
	 * @param numBytes The desired size of the resulting array.  Result is truncated or padded if 
	 *                 numBytes is smaller or larger than size of long.
	 * @return The little-endian array.
	 */
	public static byte[] toArray(long l, int numBytes) {
		ByteBuffer buffy = ByteBuffer.allocate(Long.BYTES);
		buffy.putLong(l);
		byte[] checksumArray = new byte[numBytes];
		int n = Math.min(Long.BYTES, numBytes);
		System.arraycopy(buffy.array(), Long.BYTES - n, checksumArray, numBytes - n, n);
		ArrayUtils.reverse(checksumArray);
		return checksumArray;
	}

	/**
	 * Formats the checksum as a string.
	 * 
	 * @param checksum The checksum to format as a string.
	 * @param hex True if the checksum should be formatted as hex; false if decimal. 
	 *            Note: if formatting as decimal is not possible, hex will be used instead.
	 * @return The formatted checksum.
	 */
	public static String format(byte[] checksum, boolean hex) {
		if (checksum == null || checksum.length == 0) {
			return "";
		}
		if (!hex && checksum.length <= Long.BYTES) {
			ByteBuffer buffy = ByteBuffer.allocate(Long.BYTES);
			buffy.put(new byte[Long.BYTES - checksum.length]);
			buffy.put(checksum);
			buffy.rewind();
			return Long.toUnsignedString(buffy.getLong());
		}

		return NumericUtilities.convertBytesToString(checksum);
	}

	/*
	 * Resets the checksum value to a zero length checksum.
	 */
	public void reset() {
		checksum = new byte[0];
	}
}
