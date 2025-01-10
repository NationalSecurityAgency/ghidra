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

import ghidra.pcode.emu.jit.JitPassage.ExtBranch;
import ghidra.pcode.emu.jit.JitPassage.IntBranch;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.type.TypeConversions;
import ghidra.pcode.emu.jit.gen.var.VarGen;
import ghidra.pcode.emu.jit.gen.var.VarGen.BlockTransition;
import ghidra.pcode.emu.jit.op.JitCBranchOp;

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

	@Override
	public void generateRunCode(JitCodeGenerator gen, JitCBranchOp op, JitBlock block,
			MethodVisitor rv) {

		JitType cType = gen.generateValReadCode(op.cond(), op.condType());
		TypeConversions.generateIntToBool(cType, rv);

		switch (op.branch()) {
			case IntBranch ib -> {
				JitBlock target = block.getTargetBlock(ib);
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
			case ExtBranch eb -> {
				Label fall = new Label();
				rv.visitJumpInsn(IFEQ, fall);
				BranchOpGen.generateExtBranchCode(gen, eb.to(), block, rv);
				rv.visitLabel(fall);
			}
			default -> throw new AssertionError("Branch type confusion");
		}
	}
}
