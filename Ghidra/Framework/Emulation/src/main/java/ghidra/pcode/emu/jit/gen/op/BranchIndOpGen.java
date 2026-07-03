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

import ghidra.pcode.emu.jit.JitPassage.RIndBranch;
import ghidra.pcode.emu.jit.JitPcodeThread;
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
import ghidra.pcode.emu.jit.gen.util.Types.TInt;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.pcode.emu.jit.op.JitBranchIndOp;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.RegisterValue;

/**
 * The generator for a {@link JitBranchIndOp branchind}.
 * 
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

	@Override
	public <THIS extends JitCompiledPassage> OpResult genRun(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, Local<TInt> localCtxmod, RetReq<TRef<EntryPoint>> retReq,
			JitCodeGenerator<THIS> gen, JitBranchIndOp op, JitBlock block, Scope scope) {
		return new DeadOpResult(IndBranchGen.IND.genRun(
			em, localThis, localCtxmod, retReq, gen, op, op.branch(), block));
	}
}
