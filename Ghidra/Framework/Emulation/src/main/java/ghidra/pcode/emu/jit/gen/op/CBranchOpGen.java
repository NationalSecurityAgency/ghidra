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
import ghidra.pcode.emu.jit.analysis.JitAllocationModel.RunFixedLocal;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitDataFlowModel;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.op.BranchOpGen.ExtBranchGen;
import ghidra.pcode.emu.jit.gen.op.BranchOpGen.IntBranchGen;
import ghidra.pcode.emu.jit.gen.type.TypeConversions;
import ghidra.pcode.emu.jit.gen.var.VarGen;
import ghidra.pcode.emu.jit.gen.var.VarGen.BlockTransition;
import ghidra.pcode.emu.jit.op.JitCBranchOp;
import ghidra.pcode.emu.jit.op.JitOp;
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
 * transition is necessary. If one is necessary, it emits an {@link #IFEQ ifeq} with the transition
 * and {@link #GOTO goto} it guards. The {@code ifeq} skips to the fall-through case. If a
 * transition is not necessary, it simply emits an {@link #IFNE ifne} to the target label.
 * 
 * <p>
 * With an {@link ExtBranch} record, this does the same as {@link BranchOpGen} but guarded by an
 * {@link #IFEQ ifeq} that skips to the fall-through case.
 */
public enum CBranchOpGen implements OpGen<JitCBranchOp> {
	/** The generator singleton */
	GEN;

	/**
	 * A branch code generator for internal conditional branches
	 */
	static class IntCBranchGen extends IntBranchGen {
		/** Singleton */
		static final IntCBranchGen C_INT = new IntCBranchGen();

		@Override
		void generateCodeWithoutCtxmod(JitCodeGenerator gen, JitOp op, RIntBranch branch,
				JitBlock block, MethodVisitor rv) {
			JitBlock target = block.getTargetBlock(branch);
			Label label = gen.labelForBlock(target);
			BlockTransition transition = VarGen.computeBlockTransition(gen, block, target);
			if (transition.needed()) {
				Label fall = new Label();
				rv.visitJumpInsn(IFEQ, fall);
				transition.generate(rv);
				rv.visitJumpInsn(GOTO, label);
				rv.visitLabel(fall);
			}
			else {
				rv.visitJumpInsn(IFNE, label);
			}
		}

		@Override
		void generateCodeWithCtxmod(JitCodeGenerator gen, JitOp op, Address exit, JitBlock block,
				MethodVisitor rv) {
			Label fall = new Label();
			rv.visitJumpInsn(IFEQ, fall);
			super.generateCodeWithCtxmod(gen, op, exit, block, rv);
			rv.visitLabel(fall);
		}
	}

	/**
	 * A branch code generator for external conditional branches
	 */
	static class ExtCBranchGen extends ExtBranchGen {
		/** Singleton */
		static final ExtCBranchGen C_EXT = new ExtCBranchGen();

		@Override
		void generateCodeWithoutCtxmod(JitCodeGenerator gen, JitOp op, RExtBranch branch,
				JitBlock block, MethodVisitor rv) {
			Label fall = new Label();
			rv.visitJumpInsn(IFEQ, fall);
			super.generateCodeWithoutCtxmod(gen, op, branch, block, rv);
			rv.visitLabel(fall);
		}

		@Override
		void generateCodeWithCtxmod(JitCodeGenerator gen, JitOp op, Address exit, JitBlock block,
				MethodVisitor rv) {
			Label fall = new Label();
			rv.visitJumpInsn(IFEQ, fall);
			super.generateCodeWithCtxmod(gen, op, exit, block, rv);
			rv.visitLabel(fall);
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
	public void generateRunCode(JitCodeGenerator gen, JitCBranchOp op, JitBlock block,
			MethodVisitor rv) {
		if (op.op() instanceof ExitPcodeOp && op.branch() instanceof RExtBranch eb) {
			assert eb.reach() == Reachability.MAYBE_CTXMOD;
			Label fall = new Label();
			RunFixedLocal.CTXMOD.generateLoadCode(rv);
			rv.visitJumpInsn(IFEQ, fall);
			BranchOpGen.generateExitCode(gen, eb.to().address, block, rv);
			rv.visitLabel(fall);
			return;
		}

		JitType cType = gen.generateValReadCode(op.cond(), op.condType());
		TypeConversions.generateIntToBool(cType, rv);
		switch (op.branch()) {
			case RIntBranch ib -> IntCBranchGen.C_INT.generateCode(gen, op, ib, block, rv);
			case RExtBranch eb -> ExtCBranchGen.C_EXT.generateCode(gen, op, eb, block, rv);
			default -> throw new AssertionError("Branch type confusion");
		}
	}
}
