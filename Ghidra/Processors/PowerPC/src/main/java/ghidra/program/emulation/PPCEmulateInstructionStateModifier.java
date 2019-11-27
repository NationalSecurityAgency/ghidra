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
package ghidra.program.emulation;

import java.math.BigInteger;

import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.emulate.callother.CountLeadingZerosOpBehavior;
import ghidra.pcode.emulate.callother.OpBehaviorOther;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcodeCPort.error.LowlevelError;
import ghidra.program.model.pcode.Varnode;

public class PPCEmulateInstructionStateModifier extends EmulateInstructionStateModifier {

	public PPCEmulateInstructionStateModifier(Emulate emu) {
		super(emu);

		registerPcodeOpBehavior("countLeadingZeros", new CountLeadingZerosOpBehavior());
		registerPcodeOpBehavior("vectorPermute", new vectorPermuteOpBehavior());

	}

	private class vectorPermuteOpBehavior implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {

			if (out == null) {
				throw new LowlevelError("CALLOTHER: Vector permute op missing required output");
			}

			if (inputs.length != 4) {
				throw new LowlevelError(
					"CALLOTHER: Vector permute op requires three non-constant varnode input");
			}
			for (int i = 1; i < 4; i++) {
				if (inputs[i].getSize() == 0 || inputs[i].isConstant()) {
					throw new LowlevelError(
						"CALLOTHER: Vector permute op requires three non-constant varnode input");

				}
			}

			Varnode in1 = inputs[1];
			Varnode in2 = inputs[2];
			Varnode in3 = inputs[3];
			if ((in1.getSize() != 16) || (in2.getSize() != 16) || (in3.getSize() != 16) ||
				(out.getSize() != 16)) {
				throw new LowlevelError(
					"CALLOTHER: Vector permute op inputs/output must be 16bytes long");
			}

			MemoryState memoryState = emu.getMemoryState();

			// Combine two 16-byte inputs to form single 32-byte input
			BigInteger src = memoryState.getBigInteger(in1, false);
			src = src.shiftLeft(128);
			src = src.or(memoryState.getBigInteger(in2, false));
			byte[] srcin = getUnsignedValueArray(src.toByteArray(), 32);

			// Get 16-byte permute input
			byte[] pin = memoryState.getBigInteger(in3, false).toByteArray();
			byte[] permute = getUnsignedValueArray(pin, 16);

			// Generate 16-byte output 
			byte[] outarray = new byte[16];
			for (int i = 0; i < 16; i++) {
				outarray[i] = srcin[(permute[i] & 0x1f)];
			}

			memoryState.setValue(out, new BigInteger(outarray));
		}
	}

	/**
	 * Generate an unsigned value array from variable length srcBytes extending or truncating
	 * bytes as needed to ensure a returned length of byteLength.  The MSB is located
	 * at byte index 0, therefore adjustments may be needed to ensure that the LSB retains
	 * its position in the least-significant byte.  A short srcBytes array will result in 
	 * zero-filled most-significant bytes within the result.
	 * @param srcBytes unsigned source value array
	 * @param byteLength desired result value length in bytes
	 * @return a value byte array of the specified byteLength
	 */
	private static byte[] getUnsignedValueArray(byte[] srcBytes, int byteLength) {
		if (srcBytes.length == byteLength) {
			return srcBytes;
		}
		byte[] result = new byte[byteLength];
		int srcStartIndex = Math.max(0, srcBytes.length - byteLength); // discard excessive most-significant bytes
		int copyCount = Math.min(byteLength, srcBytes.length); // limit copy to requested number of bytes
		int destStartIndex = byteLength - copyCount; // adjust if too few bytes provided
		System.arraycopy(srcBytes, srcStartIndex, result, destStartIndex, copyCount);
		return result;
	}
}
