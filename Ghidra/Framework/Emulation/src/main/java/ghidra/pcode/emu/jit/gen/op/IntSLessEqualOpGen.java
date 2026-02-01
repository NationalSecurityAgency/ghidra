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
import ghidra.pcode.emu.jit.gen.util.Emitter;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Op;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;
import ghidra.pcode.emu.jit.gen.util.Types.TLong;
import ghidra.pcode.emu.jit.op.JitIntSLessEqualOp;

/**
 * The generator for a {@link JitIntSLessEqualOp int_slessequal}.
 * 
 * <p>
 * This uses the (signed) integer comparison operator generator and simply emits
 * {@link Op#if_icmple(Emitter) if_icmple} or {@link Op#ifle(Emitter) ifle} depending on the type.
 */
public enum IntSLessEqualOpGen implements IntCompareBinOpGen<JitIntSLessEqualOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return true;
	}

	@Override
	public <N2 extends Next, N1 extends Ent<N2, TInt>, N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> opForInt(Emitter<N0> em, IntJitType type) {
		return genIntViaIfIcmp(em, Op::if_icmple);
	}

	@Override
	public <N2 extends Next, N1 extends Ent<N2, TLong>, N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TInt>> opForLong(Emitter<N0> em, LongJitType type) {
		return genLongViaLcmpThenIf(em, Op::ifle);
	}
}
