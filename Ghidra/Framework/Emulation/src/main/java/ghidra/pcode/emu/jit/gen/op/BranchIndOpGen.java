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
package ghidra.pcode.emu.jit.gen.op;

import ghidra.pcode.emu.jit.JitPassage.*;
import ghidra.pcode.emu.jit.JitPcodeThread;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.BlockFlow;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.gen.GenConsts;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator.PcGen;
import ghidra.pcode.emu.jit.gen.op.BranchOpGen.UBranchGen;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Bot;
import ghidra.pcode.emu.jit.gen.util.Emitter.Dead;
import ghidra.pcode.emu.jit.gen.util.Methods.RetReq;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.gen.var.VarGen;
import ghidra.pcode.emu.jit.op.JitBranchIndOp;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.RegisterValue;

/**
 * The generator for a {@link JitBranchIndOp branchind}.
 * <p>
 * This emits code to load the target from the operand and then retire it to the program counter,
 * along with the current flow context and live variables. It then emits code to return null so that
 * the {@link JitPcodeThread thread} knows to loop to the <b>Fetch</b> step for the new counter.
 */
public enum BranchIndOpGen implements OpGen<JitBranchIndOp> {
	/** The generator singleton */
	GEN;

	/**
	 * Generate code to retire the variables, write the dynamic pc value, and return from the
	 * passage
	 * 
	 * @param gen the code generator
	 * @param op the op
	 * @param ctx the context to write at exit, or null to not write the context
	 * @param block the block containing the op
	 * @param rv the run method visitor
	 */
	static <THIS extends JitCompiledPassage> Emitter<Dead> genExit(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, RetReq<TRef<EntryPoint>> retReq,
			JitCodeGenerator<THIS> gen, JitBranchIndOp op, RegisterValue ctx, JitBlock block) {
		PcGen tgtGen = PcGen.loadTarget(localThis, gen, op.target());
		return em
				.emit(gen::genExit, localThis, block, tgtGen, ctx)
				.emit(Op::aconst_null, GenConsts.T_ENTRY_POINT)
				.emit(Op::areturn, retReq);
	}

	/**
	 * A branch code generator for indirect branches
	 */
	static class IndBranchGen extends UBranchGen<RIndBranch, JitBranchIndOp> {
		/** Singleton */
		static final IndBranchGen IND = new IndBranchGen();

		@Override
		Address exit(JitCodeGenerator<?> gen, RIndBranch branch) {
			return null;
		}

		@Override
		<THIS extends JitCompiledPassage> Emitter<Dead> genRunWithoutCtxmod(Emitter<Bot> em,
				Local<TRef<THIS>> localThis, RetReq<TRef<EntryPoint>> retReq,
				JitCodeGenerator<THIS> gen, JitBranchIndOp op, RIndBranch branch, JitBlock block) {
			return genExit(em, localThis, retReq, gen, op, branch.flowCtx(), block);
		}

		@Override
		<THIS extends JitCompiledPassage> Emitter<Dead> genRunWithCtxmod(Emitter<Bot> em,
				Local<TRef<THIS>> localThis, Local<TInt> localCtxmod,
				RetReq<TRef<EntryPoint>> retReq, JitCodeGenerator<THIS> gen, JitBranchIndOp op,
				Address exit, JitBlock block) {
			return genExit(em, localThis, retReq, gen, op, null, block);
		}
	}

	/**
	 * A branch code generator for indirect branches which may be an internal branch
	 * <p>
	 * These occur when an indirect branch is folded to a direct branch during decode but later
	 * invalidated. The direct branch is preserved, but only taken when the run-time target happens
	 * to match the folded target.
	 */
	static class MaybeIntBranchGen extends UBranchGen<RIntBranch, JitBranchIndOp> {
		static final MaybeIntBranchGen MAYBE = new MaybeIntBranchGen();

		@Override
		Address exit(JitCodeGenerator<?> gen, RIntBranch branch) {
			return IndBranchGen.IND.exit(gen, branch.toIndBranch());
		}

		@Override
		<THIS extends JitCompiledPassage> Emitter<Dead> genRunWithoutCtxmod(Emitter<Bot> em,
				Local<TRef<THIS>> localThis, RetReq<TRef<EntryPoint>> retReq,
				JitCodeGenerator<THIS> gen, JitBranchIndOp op, RIntBranch branch, JitBlock block) {
			RIndBranch indBranch = branch.toIndBranch();
			Address intTarget = branch.to().getSeqnum().getTarget();
			PcGen targetGen = PcGen.loadTarget(localThis, gen, op.target());
			try (SubScope ss = em.rootScope().sub()) {
				Local<TLong> localTarget = ss.decl(Types.T_LONG, "target");
				PcGen missGen = PcGen.loadLocal(localTarget);
				BlockFlow flow = block.flowsFrom().get(branch);
				Lbl<Bot> intTargetLabel = gen.labelForBlock(flow.to());
				var lblHit = em
						.emit(targetGen::gen)
						.emit(Op::lstore, localTarget)
						.emit(Op::lload, localTarget)
						.emit(Op::ldc__l, intTarget.getOffset())
						.emit(Op::lcmp)
						.emit(Op::ifeq);
				return lblHit.em()
						.emit(gen::genExit, localThis, block, missGen, indBranch.flowCtx())
						.emit(Op::aconst_null, GenConsts.T_ENTRY_POINT)
						.emit(Op::areturn, retReq)
						.emit(Lbl::placeDead, lblHit.lbl())
						.emit(VarGen.computeBlockTransition(localThis, gen, flow)::genFwd)
						.emit(Op::goto_, intTargetLabel);
			}
		}

		@Override
		<THIS extends JitCompiledPassage> Emitter<Dead> genRunWithCtxmod(Emitter<Bot> em,
				Local<TRef<THIS>> localThis, Local<TInt> localCtxmod,
				RetReq<TRef<EntryPoint>> retReq, JitCodeGenerator<THIS> gen, JitBranchIndOp op,
				Address exit, JitBlock block) {
			return genExit(em, localThis, retReq, gen, op, null, block);
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @implNote No need to check for folded target. DataFlow already did, and it would have
	 *           substituted this {@link JitBranchIndOp} with something else. So, we know there's no
	 *           folded target here.
	 *           <p>
	 *           As for Indirect-or-External branches, there's little or no benefit to encoding the
	 *           run-time condition:
	 *           <ol>
	 *           <li>No internal block resulted from folding it. It remained in the queue of
	 *           externals.</li>
	 *           <li>The pseudo code is something like:
	 *           <code> t = getTarget(); if (t == folded) goto folded; else goto t;</code></li>
	 *           <li>While we might benefit from compile-time lookup of the exit slot, the run-time
	 *           conditional check is still little or no improvement over the run-time hash-map
	 *           lookup.</li>
	 *           </ol>
	 */
	@Override
	public <THIS extends JitCompiledPassage> OpResult genRun(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, Local<TInt> localCtxmod, RetReq<TRef<EntryPoint>> retReq,
			JitCodeGenerator<THIS> gen, JitBranchIndOp op, JitBlock block, Scope scope) {
		return new DeadOpResult(switch (op.branch()) {
			case RIndBranch br -> IndBranchGen.IND.genRun(em, localThis, localCtxmod, retReq, gen,
				op, br, block);
			case RIntBranch br -> MaybeIntBranchGen.MAYBE.genRun(em, localThis, localCtxmod, retReq,
				gen, op, br, block);
			case RExtBranch br -> IndBranchGen.IND.genRun(em, localThis, localCtxmod, retReq, gen,
				op, br.toIndBranch(), block);
			default -> throw new AssertionError();
		});
	}
}
