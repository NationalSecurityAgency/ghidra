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
package ghidra.pcode.emulate.callother;

import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcodeCPort.error.LowlevelError;
import ghidra.program.model.pcode.Varnode;

public class CountLeadingZerosOpBehavior implements OpBehaviorOther {

	@Override
	public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {

		if (out == null) {
			throw new LowlevelError("CALLOTHER: Count Leading Zeros op missing required output");
		}

		if (inputs.length != 2 || inputs[1].getSize() == 0 || inputs[1].isConstant()) {
			throw new LowlevelError(
				"CALLOTHER: Count Leading Zeros op requires one non-constant varnode input");
		}

		// TODO: add support for larger varnode sizes

		Varnode in = inputs[1];
		if (in.getSize() > 8 || out.getSize() > 8) {
			throw new LowlevelError(
				"CALLOTHER: Count Leading Zeros op only supports varnodes of size 8-bytes or less");
		}

		MemoryState memoryState = emu.getMemoryState();

		long value = memoryState.getValue(in);
		long mask = 1L << ((in.getSize() * 8) - 1);
		long count = 0;
		while (mask != 0) {
			if ((mask & value) != 0) {
				break;
			}
			++count;
			mask >>>= 1;
		}

		memoryState.setValue(out, count);
	}
}
