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
package ghidra.pcode.emu.jit.gen.var;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.analysis.JitTypeBehavior;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.var.JitConstVal;

/**
 * The generator for a constant value.
 * 
 * <p>
 * This can load directly the requested constant as the required JVM type onto the JVM stack. It
 * simply emits an {@link Opcodes#LDC ldc} bytecode.
 */
public enum ConstValGen implements ValGen<JitConstVal> {
	/** Singleton */
	GEN;

	@Override
	public void generateValInitCode(JitCodeGenerator gen, JitConstVal v, MethodVisitor iv) {
	}

	@Override
	public JitType generateValReadCode(JitCodeGenerator gen, JitConstVal v, JitTypeBehavior typeReq,
			MethodVisitor rv) {
		JitType type = typeReq.resolve(gen.getTypeModel().typeOf(v));
		switch (type) {
			case IntJitType t -> rv.visitLdcInsn(v.value().intValue());
			case LongJitType t -> rv.visitLdcInsn(v.value().longValue());
			case FloatJitType t -> rv.visitLdcInsn(Float.intBitsToFloat(v.value().intValue()));
			case DoubleJitType t -> rv.visitLdcInsn(Double.longBitsToDouble(v.value().longValue()));
			case MpIntJitType t -> {
				// Push most significant first, so least is at top of stack
				int count = t.legsAlloc();
				for (int i = 0; i < count; i++) {
					int leg = v.value().shiftRight(Integer.SIZE * (count - 1 - i)).intValue();
					rv.visitLdcInsn(leg);
				}
			}
			default -> throw new AssertionError();
		}
		return type;
	}
}
