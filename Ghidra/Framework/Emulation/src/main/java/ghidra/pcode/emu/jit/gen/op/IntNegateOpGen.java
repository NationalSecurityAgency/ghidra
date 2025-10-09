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

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.analysis.JitAllocationModel.JvmTempAlloc;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.op.JitIntNegateOp;

/**
 * The generator for a {@link JitIntNegateOp int_negate}.
 * 
 * <p>
 * There is no bitwise "not" operator in the JVM. We borrow the pattern we see output by the Java
 * compiler for <code>int negate(n) {return ~n;}</code>. It XORs the input with a register of 1s.
 * This uses the unary operator generator and emits the equivalent code.
 */
public enum IntNegateOpGen implements IntUnOpGen<JitIntNegateOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return false; // TODO: Is it? Test with 3-byte operands to figure it out.
	}

	private void generateMpIntNegate(JitCodeGenerator gen, MpIntJitType type, MethodVisitor mv) {
		int legCount = type.legsAlloc();
		try (JvmTempAlloc temp = gen.getAllocationModel().allocateTemp(mv, "temp", legCount)) {
			for (int i = 0; i < legCount; i++) {
				mv.visitVarInsn(ISTORE, temp.idx(i));
				// NOTE: More significant legs have higher indices (reverse of stack)
			}
			// Compute and push back in reverse order
			int i = legCount;
			for (SimpleJitType t : type.legTypes()) {
				mv.visitVarInsn(ILOAD, temp.idx(--i));
				mv.visitLdcInsn(-1 >>> (Integer.SIZE - t.size() * Byte.SIZE));
				mv.visitInsn(IXOR);
			}
		}
	}

	@Override
	public JitType generateUnOpRunCode(JitCodeGenerator gen, JitIntNegateOp op, JitBlock block,
			JitType uType, MethodVisitor rv) {
		switch (uType) {
			case IntJitType t -> {
				rv.visitLdcInsn(-1 >>> (Integer.SIZE - t.size() * Byte.SIZE));
				rv.visitInsn(IXOR);
			}
			case LongJitType t -> {
				rv.visitLdcInsn(-1L >>> (Long.SIZE - t.size() * Byte.SIZE));
				rv.visitInsn(LXOR);
			}
			case MpIntJitType t -> generateMpIntNegate(gen, t, rv);
			default -> throw new AssertionError();
		}
		return uType;
	}
}
