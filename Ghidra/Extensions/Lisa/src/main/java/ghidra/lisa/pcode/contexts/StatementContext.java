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

import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class StatementContext extends PcodeContext {

	public StatementContext otherwise;
	public StatementContext then;

	protected int opcode;
	protected Instruction inst;
	public VarDefContext left;
	public PcodeContext right;
	
	protected StatementContext(PcodeOp op) {
		super(op);
		if (op != null) {
			this.opcode = op.getOpcode();
			if (op.getOutput() != null) {
				left = new VarDefContext(op, op.getOutput());
			}
			else {
				left = new VarDefContext(op, op.getInput(2));
			}
			right = new PcodeContext(op);
		}
	}

	public StatementContext(Instruction inst, PcodeOp op) {
		this(op);
		this.inst = inst; 
	}

	public VarDefContext target() {
		return left;
	}

	public PcodeContext expression() {
		return right;
	}

	public ConditionContext condition() {
		return new ConditionContext(op);
	}

	public boolean isRet() {
		return opcode == PcodeOp.RETURN;
	}

	public boolean isBranch() {
		return opcode == PcodeOp.BRANCH || opcode == PcodeOp.BRANCHIND || opcode == PcodeOp.CBRANCH;
	}

	public boolean isConditional() {
		return opcode == PcodeOp.CBRANCH;
	}

	@Override
	public String toString() {
		return inst.getAddress() + ": " + inst + ":" + op;
	}

	public AddressFactory getAddressFactory() {
		return inst.getProgram().getAddressFactory();
	}

}
