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

import ghidra.lisa.pcode.PcodeFrontend;
import ghidra.lisa.pcode.locations.InstLocation;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import it.unive.lisa.program.CodeUnit;
import it.unive.lisa.program.Program;
import it.unive.lisa.program.SyntheticLocation;
import it.unive.lisa.program.cfg.CodeLocation;

public class UnitContext {

	protected PcodeFrontend frontend;
	protected Function function;
	protected CodeUnit unit;
	protected Address start;
	
	public UnitContext(PcodeFrontend frontend, Program program, Function f, Address entry) {
		this.frontend = frontend;
		this.function = f;
		unit = new CodeUnit(SyntheticLocation.INSTANCE, program,
			f.getName() + ":" + f.getEntryPoint());
		start = entry;
	}

	public PcodeFrontend getFrontend() {
		return frontend;
	}

	public CodeUnit unit() {
		return unit;
	}

	public String getText() {
		return function.getName();
	}

	public boolean isFinal() {
		return false;
	}

	public Listing getListing() {
		return function.getProgram().getListing();
	}

	public CodeLocation location() {
		return new InstLocation(function, start);
	}

	public Function function() {
		return function;
	}

	public InstructionContext entry() {
		Instruction inst = getListing().getInstructionAt(start);
		if (inst == null) {
			inst = getListing().getInstructionAfter(start);
		}
		return inst == null ? null : new InstructionContext(function, inst);
	}

	public List<StatementContext> branch(StatementContext ctx, Listing listing) {
		List<StatementContext> list = new ArrayList<>();	
		if (ctx.opcode == PcodeOp.BRANCH || ctx.opcode == PcodeOp.CBRANCH) {
			Varnode vn = ctx.op.getInput(0);
			if (vn.getAddress().isConstantAddress()) {
				int order = ctx.op.getSeqnum().getTime();
				order += vn.getOffset();
				list.add(new StatementContext(ctx.inst.getPcode()[order]));
			}
			else {
				Instruction next = listing.getInstructionAt(vn.getAddress().getNewAddress(vn.getOffset()));
				if (next == null || next.getPcode().length == 0) {
					return list;
				}
				list.add(new StatementContext(next, next.getPcode()[0]));
			}
		}
		if (ctx.opcode == PcodeOp.BRANCHIND) {
			ReferenceManager referenceManager = function().getProgram().getReferenceManager();
			Reference[] refs = referenceManager.getReferencesFrom(ctx.inst.getAddress());
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

	public StatementContext next(StatementContext ctx, Listing listing) {
		PcodeOp[] pcode = ctx.inst.getPcode();
		if (ctx.op != null) {
			int order = ctx.op.getSeqnum().getTime();
			if (order+1 < pcode.length) {
				return new StatementContext(ctx.inst, ctx.inst.getPcode()[order+1]);
			}
		}
		Instruction next = listing.getInstructionAt(ctx.inst.getAddress().add(ctx.inst.getLength()));
		while (next != null && next.getPcode().length == 0) {
			next = listing.getInstructionAt(next.getAddress().add(next.getLength()));
		}
		if (next == null) {
			return null;
		}
		return new StatementContext(next, next.getPcode()[0]);
	}

	public boolean contains(Address target) {
		return function.getBody().contains(target);
	}
}
