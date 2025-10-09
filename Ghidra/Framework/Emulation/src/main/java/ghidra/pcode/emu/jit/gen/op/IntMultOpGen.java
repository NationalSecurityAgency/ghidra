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
import ghidra.pcode.emu.jit.gen.type.TypeConversions.Ext;
import ghidra.pcode.emu.jit.op.JitIntMultOp;

/**
 * The generator for a {@link JitIntMultOp int_mult}.
 * 
 * <p>
 * This uses the binary operator generator and simply emits {@link #IMUL} or {@link #LMUL} depending
 * on the type.
 */
public enum IntMultOpGen implements IntBinOpGen<JitIntMultOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return false;
	}

	/**
	 * Generate the mp-int multiply code.
	 * <p>
	 * <b>NOTE:</b> I'd really like to know how many legs of the input operands are actually
	 * relevant. Very often, the following idiom is used:
	 * 
	 * <pre>
	 * temp: 16 = zext(r1) * zext(r2);
	 * r0 = temp(0);
	 * </pre>
	 * <p>
	 * That ensures all the operand sizes match, which is often (at least conventionally) required
	 * by the Sleigh compiler. However, if r1 and r2 are each only 64 bits, and I can keep track of
	 * that fact, then I could perform about half as many multiplies and adds. It also be nice if I
	 * can look ahead and see that only 64 bits of temp is actually used.
	 * <p>
	 * <b>IDEA:</b> It would be quite a change, but perhaps generating a temporary JVM-level DFG
	 * would be useful for culling. The difficulty here is knowing whether or not a temp (unique) is
	 * used by a later cross-build. Maybe with the right API calls, I could derive that without
	 * additional Sleigh compiler support. If used, I should not cull any computations, so that the
	 * retired value is the full value.
	 * 
	 * @param gen the code generator
	 * @param type the (uniform) type of the inputs and output operands
	 * @param mv the method visitor
	 */
	private void generateMpIntMult(JitCodeGenerator gen, MpIntJitType type, MethodVisitor mv) {
		BinOpGen.generateMpDelegationToStaticMethod(gen, type, "mpIntMultiply", mv, 0, TakeOut.OUT);
	}

	@Override
	public JitType afterLeft(JitCodeGenerator gen, JitIntMultOp op, JitType lType, JitType rType,
			MethodVisitor rv) {
		return TypeConversions.forceUniform(gen, lType, rType, Ext.ZERO, rv);
	}

	@Override
	public JitType generateBinOpRunCode(JitCodeGenerator gen, JitIntMultOp op, JitBlock block,
			JitType lType, JitType rType, MethodVisitor rv) {
		rType = TypeConversions.forceUniform(gen, rType, lType, Ext.ZERO, rv);
		switch (rType) {
			case IntJitType t -> rv.visitInsn(IMUL);
			case LongJitType t -> rv.visitInsn(LMUL);
			case MpIntJitType t when t.size() == lType.size() -> generateMpIntMult(gen, t, rv);
			case MpIntJitType t -> throw new AssertionError("forceUniform didn't work?");
			default -> throw new AssertionError();
		}
		// FIXME: For MpInt case, we should use the operands' (relevant) sizes to cull operations.
		return rType;
	}
}
