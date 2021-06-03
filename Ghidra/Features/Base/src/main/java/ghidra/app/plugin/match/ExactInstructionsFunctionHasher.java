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
import generic.stl.Pair;
import ghidra.program.model.lang.IncompatibleMaskException;
import ghidra.program.model.lang.Mask;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ExactInstructionsFunctionHasher extends AbstractFunctionHasher {
	public static final ExactInstructionsFunctionHasher INSTANCE =
		new ExactInstructionsFunctionHasher();

	protected MessageDigest digest;

	protected ExactInstructionsFunctionHasher() {
		this.digest = new FNV1a64MessageDigest();
	}

	@Override
	public int commonBitCount(Function funcA, Function funcB, TaskMonitor monitor) {
		int count = 0;
		Pair<Integer, ArrayList<CodeUnit>> aCodeUnitsPair =
			getAllCodeUnits(monitor, funcA.getProgram(), funcA.getBody());
		Pair<Integer, ArrayList<CodeUnit>> bCodeUnitsPair =
			getAllCodeUnits(monitor, funcB.getProgram(), funcB.getBody());
		if (aCodeUnitsPair.second.size() != bCodeUnitsPair.second.size()) {
			// This code was expecting the client to validate that the number of instructions in
			// each function is the same.   There is no easy way to do that.  Rather than force
			// the client to do that, just handle it here.  (This code is not currently used.)
			return 0;
		}

		for (int ii = 0; ii < aCodeUnitsPair.second.size(); ++ii) {
			CodeUnit aUnit = aCodeUnitsPair.second.get(ii);
			CodeUnit bUnit = aCodeUnitsPair.second.get(ii);
			try {
				byte[] aBytes = aUnit.getBytes();
				byte[] bBytes = bUnit.getBytes();
				if (aBytes.length == bBytes.length) {
					for (int jj = 0; jj < aBytes.length; ++jj) {
						count += Integer.bitCount((0xff & ~(aBytes[jj] ^ bBytes[jj])));
					}
				}
			}
			catch (MemoryAccessException e) {
				// don't worry about it; just don't add bits
			}
		}
		return count;
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
				applyMask(buffer, offset, codeUnit);
			}
			catch (MemoryAccessException e) {
				Msg.warn(this, "Could not get code unit bytes at " + codeUnit.getAddress());
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

	private static void applyMask(byte[] buffer, int offset, CodeUnit codeUnit) {
		if (!(codeUnit instanceof Instruction)) {
			return;
		}

		Instruction i = (Instruction) codeUnit;
		Mask mask = i.getPrototype().getInstructionMask();
		if (mask == null) {
			return;
		}

		try {
			mask.applyMask(buffer, offset, buffer, offset);
		}
		catch (IncompatibleMaskException e) {
			throw new RuntimeException(e);
		}

	}
}
