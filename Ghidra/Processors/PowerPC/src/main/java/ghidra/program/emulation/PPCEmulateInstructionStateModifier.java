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

import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.emulate.callother.CountLeadingZerosOpBehavior;
import ghidra.pcode.emulate.callother.OpBehaviorOther;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcodeCPort.error.LowlevelError;
import ghidra.program.model.pcode.Varnode;
import java.math.BigInteger;

public class PPCEmulateInstructionStateModifier extends EmulateInstructionStateModifier {

	
	public PPCEmulateInstructionStateModifier(Emulate emu) {
		super(emu);

        registerPcodeOpBehavior("countLeadingZeros", new CountLeadingZerosOpBehavior());
        registerPcodeOpBehavior("vectorPermute", new vectorPermuteOpBehavior());


	}

	private class vectorPermuteOpBehavior implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			int i;

			if (out == null) {
				throw new LowlevelError("CALLOTHER: Vector permute op missing required output");
			}

			if (inputs.length != 4) {
				throw new LowlevelError(
					"CALLOTHER: Vector permute op requires three non-constant varnode input");
			}
			for (i = 1; i < 4; i++) {
				if (inputs[i].getSize() == 0 || inputs[i].isConstant()) {
					throw new LowlevelError(
							"CALLOTHER: Vector permute op requires three non-constant varnode input");
					
				}
			}

			Varnode in1 = inputs[1];
			Varnode in2 = inputs[2];
			Varnode in3 = inputs[3];
			if ((in1.getSize() != 16) || (in2.getSize() != 16) || (in3.getSize() != 16) || (out.getSize() != 16)) {
				throw new LowlevelError(
					"CALLOTHER: Vector permute op inputs/output must be 16bytes long");
			}

			MemoryState memoryState = emu.getMemoryState();

			BigInteger src = memoryState.getBigInteger(in1,false);
			src = src.shiftLeft(128);
			src = src.or(memoryState.getBigInteger(in2, false));
			
			// I need to force the srcarray and permute arrays to be a specific length
			// I can find no direct way to do this which stinks.  The ensureCapacity
			// would work, but I need the padding at the beginning.
			byte[] srcin = src.toByteArray();
			byte[] srcarray;
			if (srcin.length != 32) {
				i = 32-srcin.length;
				srcarray = new byte[32];
				System.arraycopy(srcin, 0, srcarray, i, srcin.length);
			}
			else {
				srcarray = srcin;
			}
			
			byte[] pin = memoryState.getBigInteger(in3,false).toByteArray();
			byte[] permute;
			if (pin.length != 16) {
				i = 16 - pin.length;
				permute = new byte[16];
				System.arraycopy(pin, 0, permute, i, pin.length);
			}
			else {
				permute = pin;
			}
			byte[] outarray = new byte[16];
			
			for (i = 0; i < 16; i++) {
				outarray[i] = srcarray[(permute[i] & 0x1f)];
			}

			memoryState.setValue(out, new BigInteger(outarray));
		}
	}

}
