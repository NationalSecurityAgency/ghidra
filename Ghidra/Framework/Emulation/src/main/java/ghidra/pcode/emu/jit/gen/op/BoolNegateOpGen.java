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

import ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.op.JitBoolNegateOp;
import ghidra.pcode.opbehavior.OpBehaviorBoolNegate;

/**
 * The generator for a {@link JitBoolNegateOp bool_negate}.
 * <p>
 * This emits ^1, as observed in code emitted by {@code javac}. For multi-precision, we perform that
 * operation only on the least-significant leg.
 * 
 * @implNote It is the responsibility of the slaspec author to ensure boolean values are 0 or 1.
 *           This allows us to use bitwise logic instead of having to check for any non-zero value,
 *           just like {@link OpBehaviorBoolNegate}. Additionally, boolean operands ought to be a
 *           byte, but certainly no larger than an int (4 bytes).
 */
public enum BoolNegateOpGen implements IntOpUnOpGen<JitBoolNegateOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return false;
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<Ent<N1, TInt>>
			opForInt(Emitter<N0> em) {
		return em
				.emit(Op::ldc__i, 1)
				.emit(Op::ixor);
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TLong>> Emitter<Ent<N1, TLong>>
			opForLong(Emitter<N0> em) {
		return em
				.emit(Op::ldc__l, 1)
				.emit(Op::lxor);
	}

	@Override
	public <THIS extends JitCompiledPassage> Emitter<Bot> genRunMpInt(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitBoolNegateOp op,
			MpIntJitType type, Scope scope) {
		/**
		 * NOTE: This will needlessly overwrite the upper legs of the mp-int output. That said,
		 * Sleigh-spec authors should keep "boolean" operands no larger than an int, preferably a
		 * byte.
		 */
		return em
				.emit(gen::genReadLegToStack, localThis, op.u(), type, 0, ext())
				.emit(this::opForInt)
				.emit(gen::genWriteFromStack, localThis, op.out(), type.legTypesLE().getFirst(),
					ext(), scope);
	}
}
