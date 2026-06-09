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

import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.GenConsts;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.op.JitIntRemOp;

/**
 * The generator for a {@link JitIntRemOp int_rem}.
 * 
 * <p>
 * This uses the binary operator generator and simply emits
 * {@link Op#invokestatic(Emitter, TRef, String, ghidra.pcode.emu.jit.gen.util.Methods.MthDesc, boolean)}
 * on {@link Integer#remainderUnsigned(int, int)} or {@link Long#remainderUnsigned(long, long)}
 * depending on the type.
 * <p>
 * For multi-precision remainder, this emits code to invoke
 * {@link JitCompiledPassage#mpIntDivide(int[], int[], int[])}, but selects what remains in the left
 * operand as the result.
 */
public enum IntRemOpGen implements IntOpBinOpGen<JitIntRemOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return false;
	}

	@Override
	public <N2 extends Next, N1 extends Ent<N2, TInt>, N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> opForInt(Emitter<N0> em, IntJitType type) {
		return em
				.emit(Op::invokestatic, GenConsts.TR_INTEGER, "remainderUnsigned",
					GenConsts.MDESC_$INT_BINOP, false)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::ret);
	}

	@Override
	public <N2 extends Next, N1 extends Ent<N2, TLong>, N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TLong>> opForLong(Emitter<N0> em, LongJitType type) {
		return em
				.emit(Op::invokestatic, GenConsts.TR_LONG, "remainderUnsigned",
					GenConsts.MDESC_$LONG_BINOP, false)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::ret);
	}

	@Override
	public <THIS extends JitCompiledPassage> Emitter<Bot> genRunMpInt(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitIntRemOp op,
			MpIntJitType type, Scope scope) {
		return genMpDelegationToStaticMethod(em, gen, localThis, type, "mpIntDivide", op, 1,
			TakeOut.LEFT, scope);
	}
}
