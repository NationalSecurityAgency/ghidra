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

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;

public class StatementContext extends PcodeContext {

	public StatementContext otherwise;
	public StatementContext then;

	private int opcode;
	public Instruction inst;
	public VarDefContext left;
	public PcodeContext right;

	public StatementContext(Instruction inst, PcodeOp op) {
		super(op);
		this.inst = inst;
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

	public List<StatementContext> branch(Listing listing, UnitContext currentUnit) {
		List<StatementContext> list = new ArrayList<>();
		if (opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH) {
			Varnode vn = op.getInput(0);
			if (vn.getAddress().isConstantAddress()) {
				int order = op.getSeqnum().getTime();
				order += vn.getOffset();
				list.add(new StatementContext(inst, inst.getPcode()[order]));
			}
			else {
				Instruction next =
					listing.getInstructionAt(vn.getAddress().getNewAddress(vn.getOffset()));
				if (next == null || next.getPcode().length == 0) {
					return list;
				}
				list.add(new StatementContext(next, next.getPcode()[0]));
			}
		}
		if (opcode == PcodeOp.BRANCHIND) {
			ReferenceManager referenceManager =
				currentUnit.function().getProgram().getReferenceManager();
			Reference[] refs = referenceManager.getReferencesFrom(inst.getAddress());
			for (Reference ref : refs) {
				Address fromAddress = ref.getToAddress();
				Instruction next = listing.getInstructionAt(fromAddress);
				if (next == null || next.getPcode().length == 0) {
					return list;
				}
				list.add(new StatementContext(next, next.getPcode()[0]));
			}
		}
		return list;
	}

	public StatementContext next(Listing listing) {
		PcodeOp[] pcode = inst.getPcode();
		if (op != null) {
			int order = op.getSeqnum().getTime();
			if (order + 1 < pcode.length) {
				return new StatementContext(inst, inst.getPcode()[order + 1]);
			}
		}
		Instruction next = listing.getInstructionAt(inst.getAddress().add(inst.getLength()));
		while (next != null && next.getPcode().length == 0) {
			next = listing.getInstructionAt(next.getAddress().add(next.getLength()));
		}
		if (next == null) {
			return null;
		}
		return new StatementContext(next, next.getPcode()[0]);
	}

	public PcodeContext ret() {
		if (opcode == PcodeOp.RETURN) {
			return new PcodeContext(op);
		}
		return null;
	}

	@Override
	public String toString() {
		return inst.getAddress() + ": " + inst + ":" + op;
	}

}
