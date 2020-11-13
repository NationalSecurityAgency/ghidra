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

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.MemoryByteIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class is used for the computation of various basic checksums.
 */
public abstract class BasicChecksumAlgorithm extends ChecksumAlgorithm {

	/**
	 * The byte sizes that are supported by the basic checksum algorithm.
	 */
	public enum SupportedByteSize {
		CHECKSUM8(1),
		CHECKSUM16(2),
		CHECKSUM32(4);
		
		private int numBytes;

		private SupportedByteSize(int numBytes) {
			this.numBytes = numBytes;
		}

		/**
		 * Gets the number of bytes supported by this entry.
		 * 
		 * @return The number of bytes supported by this entry.
		 */
		public int getNumBytes() {
			return numBytes;
		}
	}

	private SupportedByteSize size;
	private int numBytes;

	/**
	 * Constructor for the basic checksum.
	 * 
	 * @param size The size in bytes of the basic checksum.
	 */
	public BasicChecksumAlgorithm(SupportedByteSize size) {
		super("Checksum-" + size.getNumBytes() * 8);
		this.size = size;
		this.numBytes = size.getNumBytes();
	}

	@Override
	public void updateChecksum(Memory memory, AddressSetView addrSet, TaskMonitor monitor,
			ComputeChecksumsProvider provider) throws MemoryAccessException, CancelledException {
		if (provider == null) {
			updateChecksum(memory, addrSet, monitor, false, false, false, false);
		}
		else {
			updateChecksum(memory, addrSet, monitor, provider.isXor(), provider.isCarry(),
				provider.isOnes(), provider.isTwos());
		}
	}

	/**
	 * Computes the checksum with the given options.
	 * 
	 * @param memory The memory to generate the checksum from.
	 * @param addrSet The addresses over which to generate the checksum.
	 * @param monitor Cancelable task monitor to cancel the computation.
	 * @param xor True if the checksum should allow xor operations.
	 * @param carry True if the checksum should allow carry operations.
	 * @param onesComp True if the checksum should be complemented with a ones complement.
	 * @param twosComp True if the checksum should be complemented with a twos complement.
	 * @throws MemoryAccessException If there was a problem accessing the specified memory.
	 * @throws CancelledException If checksum generation was cancelled.
	 */
	public void updateChecksum(Memory memory, AddressSetView addrSet, TaskMonitor monitor,
			boolean xor, boolean carry, boolean onesComp, boolean twosComp)
			throws MemoryAccessException, CancelledException {

		long sum = 0;
		int i = 0;
		MemoryByteIterator bytes = new MemoryByteIterator(memory, addrSet);
		while (bytes.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			long b = bytes.next() & 0xFF;
			long next = (size == SupportedByteSize.CHECKSUM8) ? b
					: b << ((numBytes - 1) - i % numBytes) * 8;
			if (xor) {
				sum ^= next;
			}
			else {
				sum += next;
			}
			i++;
		}

		// Handle carry
		if (carry) {
			long max = (long) Math.pow(2, numBytes * 8);
			while (sum >= max) {
				sum = (sum & (max - 1)) + (sum >> (numBytes * 8));
			}
		}

		// Handle complement
		if (onesComp) {
			sum = ~sum;
		}
		else if (twosComp) {
			sum = -sum;
		}

		checksum = toArray(sum, numBytes);
	}

	@Override
	public boolean supportsDecimal() {
		return true;
	}
}
