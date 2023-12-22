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

import java.util.Stack;

import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.emulate.callother.OpBehaviorOther;
import ghidra.pcode.emulate.callother.OpBehaviorOtherNOP;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.Varnode;

public class XtensaEmulateInstructionStateModifier extends EmulateInstructionStateModifier {

	private Stack<RegisterStash> stashStack = new Stack<RegisterStash>();
	public XtensaEmulateInstructionStateModifier(Emulate emu) {
		super(emu);
		
		registerPcodeOpBehavior("rotateRegWindow", new RotateRegWindow());
		registerPcodeOpBehavior("restoreRegWindow", new RestoreRegWindow());

		registerPcodeOpBehavior("swap4", new OpBehaviorOtherNOP());
		registerPcodeOpBehavior("swap8", new OpBehaviorOtherNOP());
		registerPcodeOpBehavior("swap12", new OpBehaviorOtherNOP());
		registerPcodeOpBehavior("restore4", new OpBehaviorOtherNOP());
		registerPcodeOpBehavior("restore8", new OpBehaviorOtherNOP());
		registerPcodeOpBehavior("restore12", new OpBehaviorOtherNOP());
	}

	private class RotateRegWindow implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			if (inputs.length != 2) {
				throw new LowlevelError("rotateRegWindow: missing required CALLINC input");
			}

			MemoryState memoryState = emu.getMemoryState();
			Varnode in = inputs[1];
			long callinc = memoryState.getValue(in);
			if (callinc == 0) {
				return;
			}
			if (callinc < 0 || callinc > 3) {
				throw new LowlevelError("rotateRegWindow: invalid value for CALLINC (0x" +
					Long.toHexString(callinc) + ")");
			}

			// push window onto stack
			stashStack.push(new RegisterStash((int) callinc));

			//rotate registers
			Address baseARegAddr = language.getRegister("a0").getAddress();
			int count = (int) callinc << 2; // windowSize
			long windowRegOffset = count * 4;
			count = 16 - count;

			for (int i = 0; i < count; i++) {
				Varnode fromRegVarnode =
					new Varnode(baseARegAddr.add(windowRegOffset + (i * 4)), 4);
				Varnode toRegVarnode = new Varnode(baseARegAddr.add(i * 4), 4);
				long value = memoryState.getValue(fromRegVarnode);
				memoryState.setValue(toRegVarnode, value);
			}
		}
	}

	private class RestoreRegWindow implements OpBehaviorOther {

		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			if (inputs.length != 1) {
				throw new LowlevelError("restoreRegWindow: unexpected input varnodes");
			}

			MemoryState memoryState = emu.getMemoryState();

			Register a0Reg = language.getRegister("a0");
			long callinc = (memoryState.getValue(a0Reg) >> 30) & 0x3;
			if (callinc == 0) {
				return;
			}

			if (stashStack.isEmpty()) {
				throw new LowlevelError("restoreRegWindow: window register stash is empty");
			}

			RegisterStash stash = stashStack.peek();
			if (callinc != stash.callinc) {
				throw new LowlevelError("restoreRegWindow: return address CALLINC (" + callinc +
					") does not match last entry CALLINC value (" + stash.callinc + ")");
			}

			//rotate registers
			Address baseARegAddr = language.getRegister("a0").getAddress();
			int count = (int) callinc << 2; // windowSize
			long windowRegOffset = count * 4;
			count = 16 - count;

			for (int i = 0; i < count; i++) {
				Varnode fromRegVarnode = new Varnode(baseARegAddr.add(i * 4), 4);
				Varnode toRegVarnode = new Varnode(baseARegAddr.add(windowRegOffset + (i * 4)), 4);
				long value = memoryState.getValue(fromRegVarnode);
				memoryState.setValue(toRegVarnode, value);
			}

			// remove from stack and restore
			stashStack.pop();
			stash.restore();
		}
	}

	private class RegisterStash {
		private int callinc;
		private int[] values;

		RegisterStash(int callinc) {
			this.callinc = callinc;

			MemoryState memoryState = emu.getMemoryState();
			Address baseARegAddr = language.getRegister("a0").getAddress();

			int count = callinc << 2;
			values = new int[count];

			for (int i = 0; i < count; i++) {
				Varnode regVarnode = new Varnode(baseARegAddr.add(4 * i), 4);
				values[i] = (int) memoryState.getValue(regVarnode);
			}
		}

		public void restore() {
			MemoryState memoryState = emu.getMemoryState();
			Address baseARegAddr = language.getRegister("a0").getAddress();

			for (int i = 0; i < values.length; i++) {
				Varnode regVarnode = new Varnode(baseARegAddr.add(4 * i), 4);
				memoryState.setValue(regVarnode, values[i]);
			}
		}
	}
}
