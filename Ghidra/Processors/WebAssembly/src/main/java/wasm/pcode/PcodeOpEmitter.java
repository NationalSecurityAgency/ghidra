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
package wasm.pcode;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class PcodeOpEmitter {
	private Language language;
	private Address baseAddress;
	private List<PcodeOp> ops = new ArrayList<>();

	public PcodeOpEmitter(Language language, Address baseAddress) {
		this.language = language;
		this.baseAddress = baseAddress;
	}

	public PcodeOp[] getPcodeOps() {
		if (ops.size() == 0) {
			// Work around Ghidra issue #3389: decompiler can crash if injection produces an
			// empty array
			emitNop();
		}
		return ops.toArray(new PcodeOp[0]);
	}

	private PcodeOp newOp(int opcode) {
		PcodeOp op = new PcodeOp(baseAddress, ops.size(), opcode);
		ops.add(op);
		return op;
	}

	private Varnode getRegister(String name) {
		Register register = language.getRegister(name);
		return new Varnode(register.getAddress(), register.getNumBytes());
	}

	public void emitNop() {
		PcodeOp op = newOp(PcodeOp.COPY);
		Varnode lrVarnode = getRegister("LR");
		op.setInput(lrVarnode, 0);
		op.setOutput(lrVarnode);
	}

	public void emitCopy(Address fromAddr, Address toAddr, int size) {
		/* toAddr = fromAddr */
		PcodeOp op = newOp(PcodeOp.COPY);
		op.setInput(new Varnode(fromAddr, size), 0);
		op.setOutput(new Varnode(toAddr, size));
	}
}
