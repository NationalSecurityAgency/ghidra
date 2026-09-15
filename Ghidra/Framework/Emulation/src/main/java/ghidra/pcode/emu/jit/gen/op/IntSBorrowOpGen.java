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
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.op.JitIntSBorrowOp;

/**
 * The generator for a {@link JitIntSBorrowOp int_sborrow}.
 * <p>
 * This uses the binary operator generator and emits
 * {@link Op#invokestatic(Emitter, TRef, String, ghidra.pcode.emu.jit.gen.util.Methods.MthDesc, boolean)
 * invokestatic} on {@link JitCompiledPassage#sBorrowIntRaw(int, int)} or
 * {@link JitCompiledPassage#sBorrowLongRaw(long, long)} depending on the type. We must then emit a
 * shift and mask to extract the correct bit.
 * <p>
 * For multi-precision signed borrow, we delegate to
 * {@link JitCompiledPassage#sBorrowMpInt(int[], int[], int)}, which requires no follow-on bit
 * extraction.
 */
public enum IntSBorrowOpGen implements IntPredBinOpGen<JitIntSBorrowOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return true;
	}

	@Override
	public <N2 extends Next, N1 extends Ent<N2, TInt>, N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> opForInt(Emitter<N0> em, IntJitType type) {
		return delegateIntFlagbit(em, type, "sBorrowIntRaw");
	}

	@Override
	public <N2 extends Next, N1 extends Ent<N2, TLong>, N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TInt>> opForLong(Emitter<N0> em, LongJitType type) {
		return delegateLongFlagbit(em, type, "sBorrowLongRaw");
	}

	@Override
	public <THIS extends JitCompiledPassage> Emitter<Ent<Bot, TInt>> genRunMpInt(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitIntSBorrowOp op,
			MpIntJitType type, Scope scope) {
		return delegateMpIntFlagbit(em, localThis, gen, op, type, scope, "sBorrowMpInt");
	}
}
