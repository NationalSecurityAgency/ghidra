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

import static ghidra.pcode.emu.jit.gen.GenConsts.*;

import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.op.JitLzCountOp;

/**
 * The generator for a {@link JitLzCountOp lzcount}.
 * 
 * <p>
 * This uses the unary operator generator and emits an invocation of
 * {@link Integer#numberOfLeadingZeros(int)} or {@link Long#numberOfLeadingZeros(long)}, depending
 * on the type.
 */
public enum LzCountOpGen implements IntCountUnOpGen<JitLzCountOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		/**
		 * We use zero extension and then, when there is slack, we subtract off the zero bits that
		 * came from the extension.
		 */
		return false;
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<Ent<N1, TInt>>
			opForInt(Emitter<N0> em, IntJitType type) {
		var temp = em
				.emit(Op::invokestatic, TR_INTEGER, "numberOfLeadingZeros",
					MDESC_INTEGER__NUMBER_OF_LEADING_ZEROS, false)
				.step(Inv::takeArg)
				.step(Inv::ret);
		if (type != IntJitType.I4) {
			return temp
					.emit(Op::ldc__i, Integer.SIZE - type.size() * Byte.SIZE)
					.emit(Op::isub);
		}
		return temp;
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TLong>> Emitter<Ent<N1, TInt>>
			opForLong(Emitter<N0> em, LongJitType type) {
		var temp = em
				.emit(Op::invokestatic, TR_LONG, "numberOfLeadingZeros",
					MDESC_LONG__NUMBER_OF_LEADING_ZEROS, false)
				.step(Inv::takeArg)
				.step(Inv::ret);
		if (type != LongJitType.I8) {
			return temp
					.emit(Op::ldc__i, Long.SIZE - type.size() * Byte.SIZE)
					.emit(Op::isub);
		}
		return temp;
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * The strategy here is straightforward: Start with the most-significant leg, totalling up the
	 * number of leading zeros, until we encounter a situation where the leg did not have 32 zeros.
	 * We test for this by checking if the running total is equal to 32 times the number of legs
	 * processed so far. We need not load or compute any legs beyond the point where we come up with
	 * less. When we reach the end, we made need to subtract some constant number of bits to account
	 * for types that do not occupy the full most-significant leg.
	 */
	@Override
	public <THIS extends JitCompiledPassage> Emitter<Ent<Bot, TInt>> genRunMpInt(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitLzCountOp op,
			MpIntJitType type, Scope scope) {
		/**
		 * LATER: There could be a more efficient way to do this without having to piece the leg
		 * parts together, when we're dealing with a shifted mp-int. We could instead just load the
		 * masked parts and adjust the result based on the shift.
		 */
		/**
		 * Start with the most significant and stop when we get anything other than Integer.SIZE, or
		 * right before the last.
		 */
		int legCount = type.legsAlloc();
		Lbl<Ent<Bot, TInt>> lblDone = Lbl.create();

		var emCount = em
				.emit(gen::genReadLegToStack, localThis, op.u(), type, legCount - 1, ext())
				.emit(Op::invokestatic, TR_INTEGER, "numberOfLeadingZeros",
					MDESC_INTEGER__NUMBER_OF_LEADING_ZEROS, false)
				.step(Inv::takeArg)
				.step(Inv::ret)
				.emit(Op::dup)
				.emit(Op::ldc__i, Integer.SIZE)
				.emit(Op::if_icmpne, lblDone);
		for (int i = legCount - 2; i >= 1; i--) {
			emCount = emCount
					.emit(gen::genReadLegToStack, localThis, op.u(), type, i, ext())
					.emit(Op::invokestatic, TR_INTEGER, "numberOfLeadingZeros",
						MDESC_INTEGER__NUMBER_OF_LEADING_ZEROS, false)
					.step(Inv::takeArg)
					.step(Inv::ret)
					.emit(Op::iadd)
					.emit(Op::dup)
					.emit(Op::ldc__i, Integer.SIZE * (legCount - i))
					.emit(Op::if_icmpne, lblDone);
		}
		emCount = emCount
				.emit(gen::genReadLegToStack, localThis, op.u(), type, 0, ext())
				.emit(Op::invokestatic, TR_INTEGER, "numberOfLeadingZeros",
					MDESC_INTEGER__NUMBER_OF_LEADING_ZEROS, false)
				.step(Inv::takeArg)
				.step(Inv::ret)
				.emit(Op::iadd)
				.emit(Lbl::place, lblDone);
		IntJitType mslType = type.legTypesLE().getLast();
		if (mslType != IntJitType.I4) {
			emCount = emCount
					.emit(Op::ldc__i, Integer.SIZE - mslType.size() * Byte.SIZE)
					.emit(Op::isub);
		}
		return emCount;
	}
}
