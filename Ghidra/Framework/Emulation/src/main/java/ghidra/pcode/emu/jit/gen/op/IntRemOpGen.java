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

import static ghidra.lifecycle.Unfinished.TODO;
import static ghidra.pcode.emu.jit.gen.GenConsts.*;

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.type.TypeConversions;
import ghidra.pcode.emu.jit.op.JitIntRemOp;

/**
 * The generator for a {@link JitIntRemOp int_rem}.
 * 
 * <p>
 * This uses the binary operator generator and simply emits {@link #INVOKESTATIC} on
 * {@link Integer#remainderUnsigned(int, int)} or {@link Long#remainderUnsigned(long, long)}
 * depending on the type.
 */
public enum IntRemOpGen implements BinOpGen<JitIntRemOp> {
	/** The generator singleton */
	GEN;

	@Override
	public JitType afterLeft(JitCodeGenerator gen, JitIntRemOp op, JitType lType, JitType rType,
			MethodVisitor rv) {
		return TypeConversions.forceUniformZExt(lType, rType, rv);
	}

	@Override
	public JitType generateBinOpRunCode(JitCodeGenerator gen, JitIntRemOp op, JitBlock block,
			JitType lType, JitType rType, MethodVisitor rv) {
		rType = TypeConversions.forceUniformZExt(rType, lType, rv);
		switch (rType) {
			case IntJitType t -> rv.visitMethodInsn(INVOKESTATIC, NAME_INTEGER, "remainderUnsigned",
				MDESC_$INT_BINOP, false);
			case LongJitType t -> rv.visitMethodInsn(INVOKESTATIC, NAME_LONG, "remainderUnsigned",
				MDESC_$LONG_BINOP, false);
			case MpIntJitType t -> TODO("MpInt");
			default -> throw new AssertionError();
		}
		// TODO: For MpInt case, we should use the outvar's size to cull operations.
		return lType;
	}
}
