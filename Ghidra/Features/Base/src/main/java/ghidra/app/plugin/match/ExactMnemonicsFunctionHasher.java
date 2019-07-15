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

import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ExactMnemonicsFunctionHasher extends ExactInstructionsFunctionHasher {
	@SuppressWarnings("hiding")
	public static final ExactMnemonicsFunctionHasher INSTANCE = new ExactMnemonicsFunctionHasher();

	private ExactMnemonicsFunctionHasher() {
		// use instance
	}

	@Override
	protected long hash(TaskMonitor monitor, ArrayList<CodeUnit> units, int byteCount)
			throws MemoryAccessException, CancelledException {
		StringBuilder sb = new StringBuilder();
		for (CodeUnit codeUnit : units) {
			monitor.checkCanceled();

			if (codeUnit instanceof Instruction) {
				Instruction inst = (Instruction) codeUnit;
				String mnemonic = inst.getMnemonicString();
				sb.append(mnemonic);
				// this is not allowed to be part of a mnemonic name, so it works as a separator
				sb.append("\n");
				sb.append(inst.getNumOperands());
			}
			else {
				try {
					byte[] bytes = codeUnit.getBytes();
					char[] chars = new char[bytes.length];
					for (int ii = 0; ii < bytes.length; ++ii) {
						chars[ii] = (char) bytes[ii];
					}
					sb.append(chars);
				}
				catch (MemoryAccessException e) {
					Msg.warn(this, "Could not get code unit bytes at " + codeUnit.getAddress());
					sb.append(codeUnit.getAddressString(true, true));
				}
			}
			// this is not allowed to be part of a mnemonic name, so it works as a separator
			sb.append("\n");
		}
		synchronized (digest) {
			digest.reset();
			digest.update(sb.toString().getBytes(), monitor);
			return digest.digestLong();
		}
	}
}
