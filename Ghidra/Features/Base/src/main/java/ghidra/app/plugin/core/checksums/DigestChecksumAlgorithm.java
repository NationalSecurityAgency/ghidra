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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.MemoryByteIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class is used for the computation of various digest checksums that are provided 
 * by java. These checksums do not have options associated with them.
 */
public abstract class DigestChecksumAlgorithm extends ChecksumAlgorithm {

	MessageDigest digester;

	/**
	 * Constructor for the digest checksum.
	 * 
	 * @param type The type of digest checksum to create.
	 * @throws NoSuchAlgorithmException If MessageDigest does not support the type.
	 * @see MessageDigest#getInstance(String)
	 */
	public DigestChecksumAlgorithm(String type) throws NoSuchAlgorithmException {
		super(type);
		digester = MessageDigest.getInstance(name);
	}

	@Override
	public void updateChecksum(Memory memory, AddressSetView addrSet, TaskMonitor monitor,
			ComputeChecksumsProvider provider) throws MemoryAccessException, CancelledException {
		MemoryByteIterator bytes = new MemoryByteIterator(memory, addrSet);
		while (bytes.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			digester.update(bytes.next());
		}
		checksum = digester.digest();
	}
}
