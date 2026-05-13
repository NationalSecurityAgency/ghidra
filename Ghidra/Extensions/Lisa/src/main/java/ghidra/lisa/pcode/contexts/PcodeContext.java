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
package ghidra.lisa.pcode.contexts;

import ghidra.lisa.pcode.locations.PcodeLocation;
import ghidra.program.model.pcode.PcodeOp;
import it.unive.lisa.program.SyntheticLocation;
import it.unive.lisa.program.cfg.CodeLocation;

public class PcodeContext {

	protected PcodeOp op;

	public PcodeContext(PcodeOp op) {
		this.op = op;
	}

	public PcodeOp getOp() {
		return op;
	}

	public CodeLocation location() {
		if (op == null) {
			return SyntheticLocation.INSTANCE;
		}
		return new PcodeLocation(op);
	}

	public VarnodeContext basicExpr() {
		return new VarnodeContext(op.getInput(0));
	}

	public int opcode() {
		return op.getOpcode();
	}

	public int getNumInputs() {
		return op.getNumInputs();
	}
}
