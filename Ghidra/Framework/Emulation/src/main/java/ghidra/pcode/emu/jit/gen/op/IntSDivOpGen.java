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

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.type.TypeConversions;
import ghidra.pcode.emu.jit.op.JitIntSDivOp;

/**
 * The generator for a {@link JitIntSDivOp int_sdiv}.
 * 
 * <p>
 * This uses the binary operator generator and simply emits {@link #IDIV} or {@link #LDIV} depending
 * on the type.
 */
public enum IntSDivOpGen implements IntBinOpGen<JitIntSDivOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return true;
	}

	private void generateMpIntSDiv(JitCodeGenerator gen, MpIntJitType type, MethodVisitor mv) {
		BinOpGen.generateMpDelegationToStaticMethod(gen, type, "mpIntSignedDivide", mv, 1,
			TakeOut.OUT);
	}

	@Override
	public JitType afterLeft(JitCodeGenerator gen, JitIntSDivOp op, JitType lType, JitType rType,
			MethodVisitor rv) {
		return TypeConversions.forceUniform(gen, lType, rType, ext(), rv);
	}

	@Override
	public JitType generateBinOpRunCode(JitCodeGenerator gen, JitIntSDivOp op, JitBlock block,
			JitType lType, JitType rType, MethodVisitor rv) {
		rType = TypeConversions.forceUniform(gen, rType, lType, rExt(), rv);
		switch (rType) {
			case IntJitType t -> rv.visitInsn(IDIV);
			case LongJitType t -> rv.visitInsn(LDIV);
			case MpIntJitType t when t.size() == lType.size() -> generateMpIntSDiv(gen, t, rv);
			// FIXME: forceUniform shouldn't have to enforce the same size....
			case MpIntJitType t -> throw new AssertionError("forceUniform didn't work?");
			default -> throw new AssertionError();
		}
		// TODO: For MpInt case, we should use the outvar's size to cull operations.
		return rType;
	}
}
