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
package ghidra.app.plugin.match;

import java.util.ArrayList;

import generic.hash.FNV1a64MessageDigest;
import generic.hash.MessageDigest;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ExactBytesFunctionHasher extends AbstractFunctionHasher {
	public static final ExactBytesFunctionHasher INSTANCE = new ExactBytesFunctionHasher();

	private MessageDigest digest;

	private ExactBytesFunctionHasher() {
		this.digest = new FNV1a64MessageDigest();
	}

	@Override
	public int commonBitCount(Function funcA, Function funcB, TaskMonitor monitor) {
		return (int) funcA.getBody().getNumAddresses() * 8;
	}

	@Override
	protected long hash(TaskMonitor monitor, ArrayList<CodeUnit> units, int byteCount)
			throws MemoryAccessException, CancelledException {
		byte[] buffer = new byte[byteCount];
		int offset = 0;
		for (CodeUnit codeUnit : units) {
			monitor.checkCanceled();

			try {
				codeUnit.getBytesInCodeUnit(buffer, offset);
			}
			catch (MemoryAccessException e) {
				Msg.warn(this, "Could not get code unit bvtes at " + codeUnit.getAddress());
			}
			offset += codeUnit.getLength();
		}
		if (offset != byteCount) {
			throw new IllegalStateException("did NOT use all the codeUnit buffer bytes");
		}
		synchronized (digest) {
			digest.reset();
			digest.update(buffer, monitor);
			return digest.digestLong();
		}
	}
}
