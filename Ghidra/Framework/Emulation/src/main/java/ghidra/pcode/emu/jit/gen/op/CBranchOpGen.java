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
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitDataFlowModel;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.op.BranchOpGen.*;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Bot;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Methods.RetReq;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.pcode.emu.jit.gen.var.VarGen;
import ghidra.pcode.emu.jit.gen.var.VarGen.BlockTransition;
import ghidra.pcode.emu.jit.op.JitCBranchOp;
import ghidra.pcode.emu.jit.var.JitFailVal;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;

/**
 * The generator for a {@link JitCBranchOp cbranch}.
 * 
 * <p>
 * First, emits code to load the condition onto the JVM stack.
 * 
 * <p>
 * With an {@link IntBranch} record, this looks up the label for the target block and checks if a
 * transition is necessary. If one is necessary, it emits an {@link Op#ifeq(Emitter) ifeq} with the
 * transition and {@link Op#goto_(Emitter) goto} it guards. The {@code ifeq} skips to the
 * fall-through case. If a transition is not necessary, it simply emits an {@link Op#ifne(Emitter)
 * ifne} to the target label.
 * 
 * <p>
 * With an {@link ExtBranch} record, this does the same as {@link BranchOpGen} but guarded by an
 * {@link Op#ifeq(Emitter) ifeq} that skips to the fall-through case.
 */
public enum CBranchOpGen implements OpGen<JitCBranchOp> {
	/** The generator singleton */
	GEN;

	/**
	 * An abstract branch code generator for conditional branches.
	 * 
	 * @param <TB> the type of branch
	 * @param <TO> the type of op
	 */
	abstract static class CBranchGen<TB extends RBranch, TO extends JitCBranchOp>
			extends BranchGen<Bot, Ent<Bot, TInt>, TB, TO> {
		@Override
		<THIS extends JitCompiledPassage> Emitter<Bot> genRun(Emitter<Ent<Bot, TInt>> em,
				Local<TRef<THIS>> localThis, Local<TInt> localCtxmod,
				RetReq<TRef<EntryPoint>> retReq, JitCodeGenerator<THIS> gen, TO op, TB branch,
				JitBlock block) {
			return switch (branch.reach()) {
				case WITH_CTXMOD -> genRunWithCtxmod(em, localThis, localCtxmod, retReq, gen, op,
					exit(gen, branch), block);
				case WITHOUT_CTXMOD -> genRunWithoutCtxmod(em, localThis, retReq, gen, op, branch,
					block);
				case MAYBE_CTXMOD -> {
					var lblIf = em.emit(Op::iload, localCtxmod)
							.emit(Op::ifne);
					var lblGoto = lblIf.em()
							.emit(this::genRunWithoutCtxmod, localThis, retReq, gen, op, branch,
								block)
							.emit(Op::goto_);
					yield lblGoto.em()
							.emit(Lbl::placeDead, lblIf.lbl())
							.emit(this::genRunWithCtxmod, localThis, localCtxmod, retReq, gen, op,
								exit(gen, branch), block)
							.emit(Lbl::place, lblGoto.lbl());
				}
			};
		}
	}

	/**
	 * A branch code generator for internal conditional branches
	 */
	static class IntCBranchGen extends CBranchGen<RIntBranch, JitCBranchOp> {
		/** Singleton */
		static final IntCBranchGen C_INT = new IntCBranchGen();

		@Override
		Address exit(JitCodeGenerator<?> gen, RIntBranch branch) {
			return IntBranchGen.INT.exit(gen, branch);
		}

		@Override
		<THIS extends JitCompiledPassage> Emitter<Bot> genRunWithoutCtxmod(
				Emitter<Ent<Bot, TInt>> em, Local<TRef<THIS>> localThis,
				RetReq<TRef<EntryPoint>> retReq, JitCodeGenerator<THIS> gen, JitCBranchOp op,
				RIntBranch branch, JitBlock block) {
			JitBlock target = block.getTargetBlock(branch);
			Lbl<Bot> label = gen.labelForBlock(target);
			BlockTransition<THIS> transition =
				VarGen.computeBlockTransition(localThis, gen, block, target);

			if (!transition.needed()) {
				return em
						.emit(Op::ifne, label);
			}
			var lblFall = em
					.emit(Op::ifeq);
			return lblFall.em()
					.emit(transition::genFwd)
					.emit(Op::goto_, label)
					.emit(Lbl::placeDead, lblFall.lbl());
		}

		@Override
		<THIS extends JitCompiledPassage> Emitter<Bot> genRunWithCtxmod(Emitter<Ent<Bot, TInt>> em,
				Local<TRef<THIS>> localThis, Local<TInt> localCtxmod,
				RetReq<TRef<EntryPoint>> retReq, JitCodeGenerator<THIS> gen, JitCBranchOp op,
				Address exit, JitBlock block) {
			var lblFall = em
					.emit(Op::ifeq);
			return lblFall.em()
					.emit(IntBranchGen.INT::genRunWithCtxmod, localThis, localCtxmod, retReq, gen,
						op, exit, block)
					.emit(Lbl::placeDead, lblFall.lbl());
		}
	}

	/**
	 * A branch code generator for external conditional branches
	 */
	static class ExtCBranchGen extends CBranchGen<RExtBranch, JitCBranchOp> {
		/** Singleton */
		static final ExtCBranchGen C_EXT = new ExtCBranchGen();

		@Override
		Address exit(JitCodeGenerator<?> gen, RExtBranch branch) {
			return ExtBranchGen.EXT.exit(gen, branch);
		}

		@Override
		<THIS extends JitCompiledPassage> Emitter<Bot> genRunWithoutCtxmod(
				Emitter<Ent<Bot, TInt>> em, Local<TRef<THIS>> localThis,
				RetReq<TRef<EntryPoint>> retReq, JitCodeGenerator<THIS> gen, JitCBranchOp op,
				RExtBranch branch, JitBlock block) {
			var lblFall = em
					.emit(Op::ifeq);
			return lblFall.em()
					.emit(ExtBranchGen.EXT::genRunWithoutCtxmod, localThis, retReq, gen, op, branch,
						block)
					.emit(Lbl::placeDead, lblFall.lbl());
		}

		@Override
		<THIS extends JitCompiledPassage> Emitter<Bot> genRunWithCtxmod(Emitter<Ent<Bot, TInt>> em,
				Local<TRef<THIS>> localThis, Local<TInt> localCtxmod,
				RetReq<TRef<EntryPoint>> retReq, JitCodeGenerator<THIS> gen, JitCBranchOp op,
				Address exit, JitBlock block) {
			var lblFall = em
					.emit(Op::ifeq);
			return lblFall.em()
					.emit(ExtBranchGen.EXT::genRunWithCtxmod, localThis, localCtxmod, retReq, gen,
						op, exit, block)
					.emit(Lbl::placeDead, lblFall.lbl());
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @implNote In addition to implementing the proper logic for a conditional branch, this
	 *           contains a special case for synthetic branches created using
	 *           {@link ExitPcodeOp#cond(AddrCtx)}. Such synthetic ops are employed to check for
	 *           context modification at instruction fall through. It's rare, but if there are
	 *           multiple paths in an instruction's p-code or an injection, where one causes context
	 *           modification and the other does not, then we must check for context modification at
	 *           run time.
	 *           <p>
	 *           Conventionally, all {@link PcodeOp#CBRANCH} ops should have the condition as its
	 *           second operand. Our special "conditional exit" does not. The
	 *           {@link JitDataFlowModel} recognizes this and uses {@link JitFailVal} for
	 *           {@link JitCBranchOp#cond()}. The "fail" value asserts that it never gets generated,
	 *           which will ensure we apply special handling here.
	 */
	@Override
	public <THIS extends JitCompiledPassage> LiveOpResult genRun(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, Local<TInt> localCtxmod, RetReq<TRef<EntryPoint>> retReq,
			JitCodeGenerator<THIS> gen, JitCBranchOp op, JitBlock block, Scope scope) {
		if (op.op() instanceof ExitPcodeOp && op.branch() instanceof RExtBranch eb) {
			assert eb.reach() == Reachability.MAYBE_CTXMOD;
			var lblFall = em
					.emit(Op::iload, localCtxmod)
					.emit(Op::ifeq);
			return new LiveOpResult(lblFall.em()
					.emit(BranchOpGen::genExit, localThis, retReq, gen, eb.to().address, block)
					.emit(Lbl::placeDead, lblFall.lbl()));
		}

		var emBool = gen.genReadToBool(em, localThis, op.cond());

		return new LiveOpResult(switch (op.branch()) {
			case RIntBranch ib -> IntCBranchGen.C_INT.genRun(emBool, localThis, localCtxmod, retReq,
				gen, op, ib, block);
			case RExtBranch eb -> ExtCBranchGen.C_EXT.genRun(emBool, localThis, localCtxmod, retReq,
				gen, op, eb, block);
			default -> throw new AssertionError();
		});
	}
}
