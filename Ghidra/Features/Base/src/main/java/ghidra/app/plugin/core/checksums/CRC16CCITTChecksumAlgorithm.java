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
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class is used for the computation of the CRC-16 CCITT checksum algorithm.
 */
public class CRC16CCITTChecksumAlgorithm extends ChecksumAlgorithm {

	/**
	 * Constructor for the CRC-16 CCITT checksum algorithm.
	 */
	public CRC16CCITTChecksumAlgorithm() {
		super("CRC-16-CCITT");
	}

	@Override
	public void updateChecksum(Memory memory, AddressSetView addrSet, TaskMonitor monitor,
			ComputeChecksumsProvider provider) throws MemoryAccessException, CancelledException {
		if (provider == null) {
			updateChecksum(memory, addrSet, monitor, false, false);
		}
		else {
			updateChecksum(memory, addrSet, monitor, provider.isOnes(), provider.isTwos());
		}
	}

	/**
	 * Computes the checksum with the given options.
	 * 
	 * @param memory The memory to generate the checksum from.
	 * @param addrSet The addresses over which to generate the checksum.
	 * @param monitor Cancelable task monitor to cancel the computation.
	 * @param onesComp True if the checksum should be complemented with a ones complement.
	 * @param twosComp True if the checksum should be complemented with a twos complement.
	 * @throws MemoryAccessException If there was a problem reading the memory.
	 * @throws CancelledException If the user cancels the task.
	 */
	public void updateChecksum(Memory memory, AddressSetView addrSet, TaskMonitor monitor,
			boolean onesComp, boolean twosComp) throws MemoryAccessException, CancelledException {
		int entry = 0;
		int[] ccitt_table = new int[256];
		for (int i = 0; i < 256; i++) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}

			entry = i << 8;
			for (int j = 0; j < 8; j++) {
				if ((entry & 0x8000) > 0) {
					entry = (entry << 1) ^ 0x1021;
				}
				else {
					entry <<= 1;
				}
			}
			String value = Integer.toHexString(entry);
			if (value.length() > 4) {
				value = value.substring(value.length() - 4);
			}
			ccitt_table[i] = Integer.parseInt(value, 16);
		}
		long sum = 0xffff;
		MemoryByteIterator it = new MemoryByteIterator(memory, addrSet);
		while (it.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			byte b = it.next();
			int value = 0;
			if (b < 0) {
				value = b + 256;
			}
			else {
				value = b;
			}
			int element = (int) ((sum >>> 8) & 0xff) ^ value;
			String loworder = Long.toHexString(sum);
			if (loworder.length() >= 2) {
				loworder = loworder.substring(loworder.length() - 2);
			}
			sum = ccitt_table[element] ^ (NumericUtilities.parseHexLong(loworder) << 8);
		}
		if (onesComp) {
			sum = ~sum;
		}
		else if (twosComp) {
			sum = -sum;
		}
		checksum = toArray(sum, 2);
	}

	@Override
	public boolean supportsDecimal() {
		return true;
	}
}
