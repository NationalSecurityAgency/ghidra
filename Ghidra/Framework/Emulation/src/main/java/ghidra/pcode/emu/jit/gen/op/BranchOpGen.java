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
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.gen.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator.PcGen;
import ghidra.pcode.emu.jit.gen.op.CBranchOpGen.ExtCBranchGen;
import ghidra.pcode.emu.jit.gen.op.CBranchOpGen.IntCBranchGen;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Methods.RetReq;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.pcode.emu.jit.gen.var.VarGen;
import ghidra.pcode.emu.jit.op.JitBranchOp;
import ghidra.pcode.emu.jit.op.JitOp;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.RegisterValue;

/**
 * The generator for a {@link JitBranchOp branch}.
 * 
 * <p>
 * With an {@link IntBranch} record, this simply looks up the label for the target block and emits a
 * block transition followed by a {@link Op#goto_(Emitter) goto}.
 * 
 * <p>
 * With an {@link ExtBranch} record, this emits code to retire the target to the program counter,
 * along with the target context and live variables. It then emits code to request the chained entry
 * point from the target's exit slot and return it. The {@link JitPcodeThread thread} can then
 * immediately execute the chained passage entry.
 */
public enum BranchOpGen implements OpGen<JitBranchOp> {
	/** The generator singleton */
	GEN;

	/**
	 * Generate code to retire the variables and write a given pc value.
	 * 
	 * @param gen the code generator
	 * @param exit the pc value to write
	 * @param ctx the context to write at exit, or null to not write the context
	 * @param block the block containing the op
	 * @param rv the run method visitor
	 */
	static <THIS extends JitCompiledPassage> Emitter<Bot> genRetire(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, Address exit,
			RegisterValue ctx, JitBlock block) {
		return gen.genExit(em, localThis, block, PcGen.loadOffset(exit), ctx);
	}

	/**
	 * Generate code to retire the variables, write a given pc value, and return from the passage.
	 * 
	 * <p>
	 * This will not write any decode context.
	 * 
	 * @param gen the code generator
	 * @param exit the pc value to write
	 * @param block the block containing the op
	 * @param rv the run method visitor
	 */
	static <THIS extends JitCompiledPassage> Emitter<Dead> genExit(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, RetReq<TRef<EntryPoint>> retReq,
			JitCodeGenerator<THIS> gen, Address exit, JitBlock block) {
		return em
				.emit(BranchOpGen::genRetire, localThis, gen, exit, (RegisterValue) null, block)
				.emit(Op::aconst_null, GenConsts.T_ENTRY_POINT)
				.emit(Op::areturn, retReq);
	}

	/**
	 * A branch code generator
	 * 
	 * @param <NR> the stack after the JVM branch bytecode (may be {@link Dead})
	 * @param <NI> the stack before the JVM branch bytecode (cannot be {@link Dead})
	 * @param <TB> the type of branch
	 * @param <TO> the type of op
	 */
	static abstract class BranchGen<NR, NI extends Next, TB extends RBranch, TO extends JitOp> {
		/**
		 * Get the target address of the branch
		 * 
		 * @param gen the code generator
		 * @param branch the branch
		 * @return the target address
		 */
		abstract Address exit(JitCodeGenerator<?> gen, TB branch);

		/**
		 * Generate code for the branch in the case a context modification has not occurred.
		 * 
		 * <p>
		 * This means <em>no</em> context-modifying userop has been invoked.
		 * 
		 * @param gen the code generator
		 * @param op the branch op
		 * @param branch the branch from the op
		 * @param block the block containing the op
		 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
		 */
		abstract <THIS extends JitCompiledPassage> Emitter<NR> genRunWithoutCtxmod(Emitter<NI> em,
				Local<TRef<THIS>> localThis, RetReq<TRef<EntryPoint>> retReq,
				JitCodeGenerator<THIS> gen, TO op, TB branch, JitBlock block);

		/**
		 * Generate code for the branch in the case a context modification may have occurred.
		 * 
		 * <p>
		 * This means a context-modifying userop has <em>certainly</em> been invoked, but not
		 * necessarily that the context has actually changed.
		 * 
		 * @param gen the code generator
		 * @param op the branch op
		 * @param branch the branch from the op
		 * @param block the block containing the op
		 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
		 */
		abstract <THIS extends JitCompiledPassage> Emitter<NR> genRunWithCtxmod(Emitter<NI> em,
				Local<TRef<THIS>> localThis, Local<TInt> localCtxmod,
				RetReq<TRef<EntryPoint>> retReq, JitCodeGenerator<THIS> gen, TO op, Address exit,
				JitBlock block);

		/**
		 * Emit code that jumps or exits via a direct branch
		 * 
		 * @param gen the code generator
		 * @param op the branch op
		 * @param branch the branch from the op
		 * @param block the block containing the op
		 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
		 */
		abstract <THIS extends JitCompiledPassage> Emitter<NR> genRun(Emitter<NI> em,
				Local<TRef<THIS>> localThis, Local<TInt> localCtxmod,
				RetReq<TRef<EntryPoint>> retReq, JitCodeGenerator<THIS> gen, TO op, TB branch,
				JitBlock block);
	}

	/**
	 * An abstract branch code generator for unconditional branches.
	 * 
	 * @param <TB> the type of branch
	 * @param <TO> the type of op
	 */
	abstract static class UBranchGen<TB extends RBranch, TO extends JitOp>
			extends BranchGen<Dead, Bot, TB, TO> {
		/**
		 * Emit code that jumps or exits via a direct branch
		 * 
		 * @param gen the code generator
		 * @param op the branch op
		 * @param branch the branch from the op
		 * @param block the block containing the op
		 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
		 */
		@Override
		<THIS extends JitCompiledPassage> Emitter<Dead> genRun(Emitter<Bot> em,
				Local<TRef<THIS>> localThis, Local<TInt> localCtxmod,
				RetReq<TRef<EntryPoint>> retReq, JitCodeGenerator<THIS> gen, TO op, TB branch,
				JitBlock block) {
			return switch (branch.reach()) {
				case WITH_CTXMOD -> genRunWithCtxmod(em, localThis, localCtxmod, retReq, gen, op,
					exit(gen, branch), block);
				case WITHOUT_CTXMOD -> genRunWithoutCtxmod(em, localThis, retReq, gen, op, branch,
					block);
				case MAYBE_CTXMOD -> {
					var emIf = em
							.emit(Op::iload, localCtxmod)
							.emit(Op::ifne);
					yield emIf.em()
							.emit(this::genRunWithoutCtxmod, localThis, retReq, gen, op, branch,
								block)
							.emit(Lbl::placeDead, emIf.lbl())
							// NB. genRun is already branching. No need for if-else construct.
							.emit(this::genRunWithCtxmod, localThis, localCtxmod, retReq, gen, op,
								exit(gen, branch), block);
				}
			};
		}
	}

	/**
	 * A branch code generator for internal branches
	 * 
	 * @implNote We leave {@code TO:=}{@link JitOp} here, because we want {@link IntCBranchGen} to
	 *           be able to delegate to this instance.
	 */
	static class IntBranchGen extends UBranchGen<RIntBranch, JitOp> {
		/** Singleton */
		static final IntBranchGen INT = new IntBranchGen();

		@Override
		Address exit(JitCodeGenerator<?> gen, RIntBranch branch) {
			return gen.getAddressForOp(branch.to());
		}

		@Override
		<THIS extends JitCompiledPassage> Emitter<Dead> genRunWithoutCtxmod(Emitter<Bot> em,
				Local<TRef<THIS>> localThis, RetReq<TRef<EntryPoint>> retReq,
				JitCodeGenerator<THIS> gen, JitOp op, RIntBranch branch, JitBlock block) {
			JitBlock target = block.getTargetBlock(branch);
			Lbl<Bot> label = gen.labelForBlock(target);
			return em
					.emit(VarGen.computeBlockTransition(localThis, gen, block, target)::genFwd)
					.emit(Op::goto_, label);
		}

		@Override
		<THIS extends JitCompiledPassage> Emitter<Dead> genRunWithCtxmod(Emitter<Bot> em,
				Local<TRef<THIS>> localThis, Local<TInt> localCtxmod,
				RetReq<TRef<EntryPoint>> retReq, JitCodeGenerator<THIS> gen, JitOp op, Address exit,
				JitBlock block) {
			return genExit(em, localThis, retReq, gen, exit, block);
		}
	}

	/**
	 * A branch code generator for external branches
	 * 
	 * @implNote We leave {@code TO:=}{@link JitOp} here, because we want {@link ExtCBranchGen} to
	 *           be able to delegate to this instance.
	 */
	static class ExtBranchGen extends UBranchGen<RExtBranch, JitOp> {
		/** Singleton */
		static final ExtBranchGen EXT = new ExtBranchGen();

		@Override
		Address exit(JitCodeGenerator<?> gen, RExtBranch branch) {
			return branch.to().address;
		}

		@Override
		<THIS extends JitCompiledPassage> Emitter<Dead> genRunWithoutCtxmod(Emitter<Bot> em,
				Local<TRef<THIS>> localThis, RetReq<TRef<EntryPoint>> retReq,
				JitCodeGenerator<THIS> gen, JitOp op, RExtBranch branch, JitBlock block) {
			AddrCtx exit = branch.to();
			FieldForExitSlot slotField = gen.requestFieldForExitSlot(exit);
			return em
					.emit(BranchOpGen::genRetire, localThis, gen, exit.address, exit.rvCtx, block)
					.emit(slotField::genLoad, localThis, gen)
					.emit(Op::invokestatic, GenConsts.T_JIT_COMPILED_PASSAGE, "getChained",
						GenConsts.MDESC_JIT_COMPILED_PASSAGE__GET_CHAINED, true)
					.step(Inv::takeArg)
					.step(Inv::ret)
					.emit(Op::areturn, retReq);
		}

		@Override
		<THIS extends JitCompiledPassage> Emitter<Dead> genRunWithCtxmod(Emitter<Bot> em,
				Local<TRef<THIS>> localThis, Local<TInt> localCtxmod,
				RetReq<TRef<EntryPoint>> retReq, JitCodeGenerator<THIS> gen, JitOp op, Address exit,
				JitBlock block) {
			return genExit(em, localThis, retReq, gen, exit, block);
		}
	}

	@Override
	public <THIS extends JitCompiledPassage> DeadOpResult genRun(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, Local<TInt> localCtxmod, RetReq<TRef<EntryPoint>> retReq,
			JitCodeGenerator<THIS> gen, JitBranchOp op, JitBlock block, Scope scope) {
		return new DeadOpResult(switch (op.branch()) {
			case RIntBranch ib -> IntBranchGen.INT.genRun(em, localThis, localCtxmod, retReq, gen,
				op, ib, block);
			case RExtBranch eb -> ExtBranchGen.EXT.genRun(em, localThis, localCtxmod, retReq, gen,
				op, eb, block);
			default -> throw new AssertionError("Branch type confusion");
		});
	}
}
