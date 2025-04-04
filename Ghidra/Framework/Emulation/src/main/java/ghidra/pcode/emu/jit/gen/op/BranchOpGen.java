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

import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.JitPassage.*;
import ghidra.pcode.emu.jit.JitPcodeThread;
import ghidra.pcode.emu.jit.analysis.JitAllocationModel.RunFixedLocal;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.gen.*;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
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
 * block transition followed by a {@link #GOTO goto}.
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
	static void generateRetireCode(JitCodeGenerator gen, Address exit, RegisterValue ctx,
			JitBlock block, MethodVisitor rv) {
		gen.generatePassageExit(block, () -> {
			// [...]
			rv.visitLdcInsn(exit.getOffset());
			// [...,target:LONG]
		}, ctx, rv);
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
	static void generateExitCode(JitCodeGenerator gen, Address exit, JitBlock block,
			MethodVisitor rv) {
		generateRetireCode(gen, exit, null, block, rv);
		rv.visitInsn(ACONST_NULL);
		rv.visitInsn(ARETURN);
	}

	/**
	 * A branch code generator
	 * 
	 * @param <TB> the type of branch
	 * @param <TO> the type of op
	 */
	static abstract class BranchGen<TB extends RBranch, TO extends JitOp> {
		/**
		 * Get the target address of the branch
		 * 
		 * @param gen the code generator
		 * @param branch the branch
		 * @return the target address
		 */
		abstract Address exit(JitCodeGenerator gen, TB branch);

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
		abstract void generateCodeWithoutCtxmod(JitCodeGenerator gen, TO op, TB branch,
				JitBlock block, MethodVisitor rv);

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
		abstract void generateCodeWithCtxmod(JitCodeGenerator gen, TO op, Address exit,
				JitBlock block, MethodVisitor rv);

		/**
		 * Emit code that jumps or exits via a direct branch
		 * 
		 * @param gen the code generator
		 * @param op the branch op
		 * @param branch the branch from the op
		 * @param block the block containing the op
		 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
		 */
		void generateCode(JitCodeGenerator gen, TO op, TB branch, JitBlock block,
				MethodVisitor rv) {
			switch (branch.reach()) {
				case WITH_CTXMOD -> generateCodeWithCtxmod(gen, op, exit(gen, branch), block, rv);
				case WITHOUT_CTXMOD -> generateCodeWithoutCtxmod(gen, op, branch, block, rv);
				case MAYBE_CTXMOD -> {
					Label withModctx = new Label();
					RunFixedLocal.CTXMOD.generateLoadCode(rv);
					rv.visitJumpInsn(IFNE, withModctx);
					generateCodeWithoutCtxmod(gen, op, branch, block, rv);
					rv.visitLabel(withModctx);
					generateCodeWithCtxmod(gen, op, exit(gen, branch), block, rv);
				}
				default -> throw new AssertionError();
			}
		}
	}

	/**
	 * A branch code generator for internal branches
	 */
	static class IntBranchGen extends BranchGen<RIntBranch, JitOp> {
		/** Singleton */
		static final IntBranchGen INT = new IntBranchGen();

		@Override
		Address exit(JitCodeGenerator gen, RIntBranch branch) {
			return gen.getAddressForOp(branch.to());
		}

		@Override
		void generateCodeWithoutCtxmod(JitCodeGenerator gen, JitOp op, RIntBranch branch,
				JitBlock block, MethodVisitor rv) {
			JitBlock target = block.getTargetBlock(branch);
			Label label = gen.labelForBlock(target);
			VarGen.computeBlockTransition(gen, block, target).generate(rv);
			rv.visitJumpInsn(GOTO, label);
		}

		@Override
		void generateCodeWithCtxmod(JitCodeGenerator gen, JitOp op, Address exit, JitBlock block,
				MethodVisitor rv) {
			generateExitCode(gen, exit, block, rv);
		}
	}

	/**
	 * A branch code generator for external branches
	 */
	static class ExtBranchGen extends BranchGen<RExtBranch, JitOp> {
		/** Singleton */
		static final ExtBranchGen EXT = new ExtBranchGen();

		@Override
		Address exit(JitCodeGenerator gen, RExtBranch branch) {
			return branch.to().address;
		}

		@Override
		void generateCodeWithoutCtxmod(JitCodeGenerator gen, JitOp op, RExtBranch branch,
				JitBlock block, MethodVisitor rv) {
			AddrCtx exit = branch.to();
			FieldForExitSlot slotField = gen.requestFieldForExitSlot(exit);

			generateRetireCode(gen, exit.address, exit.rvCtx, block, rv);

			// []
			slotField.generateLoadCode(gen, rv);
			// [slot]
			rv.visitMethodInsn(INVOKESTATIC, GenConsts.NAME_JIT_COMPILED_PASSAGE, "getChained",
				GenConsts.MDESC_JIT_COMPILED_PASSAGE__GET_CHAINED, true);
			// [chained:ENTRY]
			rv.visitInsn(ARETURN);
		}

		@Override
		void generateCodeWithCtxmod(JitCodeGenerator gen, JitOp op, Address exit, JitBlock block,
				MethodVisitor rv) {
			generateExitCode(gen, exit, block, rv);
		}
	}

	@Override
	public void generateRunCode(JitCodeGenerator gen, JitBranchOp op, JitBlock block,
			MethodVisitor rv) {
		switch (op.branch()) {
			case RIntBranch ib -> IntBranchGen.INT.generateCode(gen, op, ib, block, rv);
			case RExtBranch eb -> ExtBranchGen.EXT.generateCode(gen, op, eb, block, rv);
			default -> throw new AssertionError("Branch type confusion");
		}
	}
}
