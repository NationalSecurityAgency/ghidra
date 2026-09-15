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

import java.util.*;

import ghidra.lisa.pcode.PcodeFrontend;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.*;
import it.unive.lisa.program.Program;

public class HighUnitContext extends UnitContext {

	// High pcode-only
	private HighFunction hfunc;
	Map<SequenceNumber, HighStatementContext> map = new HashMap<>();

	public HighUnitContext(PcodeFrontend frontend, Program program, Function f, HighFunction hfunc, Address entry) {
		super(frontend, program, f, entry);
		this.hfunc = hfunc;
	}

	@Override
	public InstructionContext entry() {
		return initEdges();
	}

	@Override
	public List<StatementContext> branch(StatementContext ctx, Listing listing) {
		if (ctx instanceof HighStatementContext hctx) {
			return hctx.getBranches();
		}
		return new ArrayList<StatementContext>();
	}

	@Override
	public HighStatementContext next(StatementContext ctx, Listing listing) {
		if (ctx instanceof HighStatementContext hctx) {
			return hctx.getNext();
		}
		return null;
	}

	public void setBranches(PcodeBlockBasic bb) {
		PcodeOp lastOp = bb.getLastOp();
		HighStatementContext ctx = map.get(lastOp.getSeqnum());
		for (int i = 0; i < bb.getOutSize(); i++) {
			if (bb.getOut(i) instanceof PcodeBlockBasic basic) {
				PcodeOp op = basic.getFirstOp();
				if (lastOp.getOpcode() == PcodeOp.CBRANCH) {
					if (basic.equals(bb.getFalseOut())) {
						ctx.setNext(map.get(op.getSeqnum()));
					}
					else {
						ctx.addBranch(map.get(op.getSeqnum()));
					}
				}
				else if (lastOp.getOpcode() == PcodeOp.BRANCH ||
					lastOp.getOpcode() == PcodeOp.BRANCHIND) {
					ctx.addBranch(map.get(op.getSeqnum()));
				}
				else {
					ctx.setNext(map.get(op.getSeqnum()));
				}
			}
		}
	}

	private InstructionContext initEdges() {
		Iterator<PcodeOpAST> pcodeOps = hfunc.getPcodeOps();
		while (pcodeOps.hasNext()) {
			PcodeOpAST next = pcodeOps.next();
			HighStatementContext ctx = new HighStatementContext(hfunc, next);
			map.put(next.getSeqnum(), ctx);
		}
		ArrayList<PcodeBlockBasic> basicBlocks = hfunc.getBasicBlocks();
		HighStatementContext first = null;
		for (PcodeBlockBasic b : basicBlocks) {
			Iterator<PcodeOp> iterator = b.getIterator();
			PcodeOp prev = null;
			while (iterator.hasNext()) {
				PcodeOp next = iterator.next();
				HighStatementContext n = map.get(next.getSeqnum());
				if (prev != null) {
					HighStatementContext p = map.get(prev.getSeqnum());
					if (p != null && n != null) {
						p.setNext(n);
						n.setPrev(p);
					}
				}
				else if (first == null) {
					first = n;			
				}
				prev = next;
			}
		}
		for (PcodeBlockBasic b : basicBlocks) {
			setBranches(b);
		}
		return new HighInstructionContext(first);
	}

}
