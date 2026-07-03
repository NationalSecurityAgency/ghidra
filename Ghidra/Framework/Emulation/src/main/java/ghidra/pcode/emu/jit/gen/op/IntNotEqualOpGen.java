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

import ghidra.pcode.emu.jit.analysis.JitType.IntJitType;
import ghidra.pcode.emu.jit.analysis.JitType.LongJitType;
import ghidra.pcode.emu.jit.gen.GenConsts;
import ghidra.pcode.emu.jit.gen.util.Emitter;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Op;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;
import ghidra.pcode.emu.jit.gen.util.Types.TLong;
import ghidra.pcode.emu.jit.op.JitIntNotEqualOp;

/**
 * The generator for a {@link JitIntNotEqualOp int_notequal}.
 * 
 * <p>
 * To avoid jumps, this delegates to {@link Integer#compare(int, int)}, which is signed, and then
 * masks the result.
 */
public enum IntNotEqualOpGen implements IntCompareBinOpGen<JitIntNotEqualOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return true; // Doesn't matter. Java favors signed.
	}

	@Override
	public <N2 extends Next, N1 extends Ent<N2, TInt>, N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> opForInt(Emitter<N0> em, IntJitType type) {
		return em
				.emit(Op::invokestatic, GenConsts.TR_INTEGER, "compare",
					GenConsts.MDESC_INTEGER__COMPARE, false)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::ret)
				.emit(Op::ldc__i, 1)
				.emit(Op::iand);
		// LATER: Can probably remove this mask 1. Tests check it, but still.
	}

	@Override
	public <N2 extends Next, N1 extends Ent<N2, TLong>, N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TInt>> opForLong(Emitter<N0> em, LongJitType type) {
		return em
				.emit(Op::lcmp)
				.emit(Op::ldc__i, 1)
				.emit(Op::iand);
		// LATER: Can probably remove this mask 1. Tests check it, but still.
	}
}
