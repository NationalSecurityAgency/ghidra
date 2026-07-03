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
import ghidra.pcode.emu.jit.op.JitPopCountOp;

/**
 * The generator for a {@link JitPopCountOp popcount}.
 * 
 * <p>
 * This uses the unary operator generator and emits an invocation of {@link Integer#bitCount(int)}
 * or {@link Long#bitCount(long)}, depending on the type.
 */
public enum PopCountOpGen implements IntCountUnOpGen<JitPopCountOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return false;
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<Ent<N1, TInt>>
			opForInt(Emitter<N0> em, IntJitType type) {
		return em
				.emit(Op::invokestatic, TR_INTEGER, "bitCount", MDESC_INTEGER__BIT_COUNT, false)
				.step(Inv::takeArg)
				.step(Inv::ret);
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TLong>> Emitter<Ent<N1, TInt>>
			opForLong(Emitter<N0> em, LongJitType type) {
		return em
				.emit(Op::invokestatic, TR_LONG, "bitCount", MDESC_LONG__BIT_COUNT, false)
				.step(Inv::takeArg)
				.step(Inv::ret);
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * The strategy here is to simply total the pop count from every leg.
	 */
	@Override
	public <THIS extends JitCompiledPassage> Emitter<Ent<Bot, TInt>> genRunMpInt(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitPopCountOp op,
			MpIntJitType type, Scope scope) {
		int legCount = type.legsAlloc();

		var emCount = em
				.emit(gen::genReadLegToStack, localThis, op.u(), type, 0, ext())
				.emit(this::opForInt, IntJitType.I4);
		for (int i = 1; i < legCount; i++) {
			emCount = emCount
					.emit(gen::genReadLegToStack, localThis, op.u(), type, i, ext())
					.emit(this::opForInt, IntJitType.I4)
					.emit(Op::iadd);
		}
		return emCount;
	}
}
