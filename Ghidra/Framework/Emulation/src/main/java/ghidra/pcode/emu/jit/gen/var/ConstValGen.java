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

import java.math.BigInteger;

import org.objectweb.asm.Opcodes;

import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.Opnd;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.OpndEm;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.*;
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
	public <THIS extends JitCompiledPassage, N extends Next> Emitter<N> genValInit(Emitter<N> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitConstVal v) {
		return em;
	}

	@Override
	public <THIS extends JitCompiledPassage, T extends BPrim<?>, JT extends SimpleJitType<T, JT>,
		N extends Next> Emitter<Ent<N, T>> genReadToStack(Emitter<N> em,
				Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitConstVal v, JT type,
				Ext ext) {
		return switch (type) {
			case IntJitType t -> em
					.emit(Op::ldc__i, v.value().intValue())
					.emit(ValGen::castBack, type, t);
			case LongJitType t -> em
					.emit(Op::ldc__l, v.value().longValue())
					.emit(ValGen::castBack, type, t);
			case FloatJitType t -> em
					.emit(Op::ldc__f, Float.intBitsToFloat(v.value().intValue()))
					.emit(ValGen::castBack, type, t);
			case DoubleJitType t -> em
					.emit(Op::ldc__d, Double.longBitsToDouble(v.value().longValue()))
					.emit(ValGen::castBack, type, t);
			default -> throw new AssertionError();
		};
	}

	@Override
	public <THIS extends JitCompiledPassage, N extends Next> OpndEm<MpIntJitType, N> genReadToOpnd(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitConstVal v,
			MpIntJitType type, Ext ext, Scope scope) {
		return new OpndEm<>(Opnd.constOf(type, v.value()), em);
	}

	@Override
	public <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TInt>>
			genReadLegToStack(Emitter<N> em, Local<TRef<THIS>> localThis,
					JitCodeGenerator<THIS> gen, JitConstVal v, MpIntJitType type, int leg,
					Ext ext) {
		BigInteger value = v.value();
		int legVal = value.shiftRight(leg * Integer.SIZE).intValue();
		return em
				.emit(Op::ldc__i, legVal);
	}

	@Override
	public <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TRef<int[]>>>
			genReadToArray(Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen,
					JitConstVal v, MpIntJitType type, Ext ext, Scope scope, int slack) {
		int legCount = type.legsAlloc();
		var ckArr = em
				.emit(Op::ldc__i, legCount + slack)
				.emit(Op::newarray, Types.T_INT);
		BigInteger value = v.value();
		for (int i = 0; i < legCount; i++) {
			int leg = value.intValue();
			if (leg != 0) {
				ckArr = ckArr
						.emit(Op::dup)
						.emit(Op::ldc__i, i)
						.emit(Op::ldc__i, leg)
						.emit(Op::iastore);
			}
		}
		return ckArr;
	}

	@Override
	public <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TInt>> genReadToBool(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitConstVal v) {
		return em.emit(Op::ldc__i, v.value().equals(BigInteger.ZERO) ? 0 : 1);
	}

	@Override
	public ValGen<JitConstVal> subpiece(int byteShift, int maxByteSize) {
		throw new AssertionError("Sleigh compiler generated subpiece of a constant?");
	}
}
