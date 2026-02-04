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
import ghidra.pcode.emu.jit.op.JitIntSRemOp;

/**
 * The generator for a {@link JitIntSRemOp int_srem}.
 * 
 * <p>
 * This uses the binary operator generator and simply emits {@link Op#irem(Emitter) irem} or
 * {@link Op#lrem(Emitter) lrem} depending on the type.
 * <p>
 * For multi-precision remainder, this emits code to invoke
 * {@link JitCompiledPassage#mpIntSignedDivide(int[], int[], int[])}, but selects what remains in
 * the left operand as the result.
 */
public enum IntSRemOpGen implements IntOpBinOpGen<JitIntSRemOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return true;
	}

	@Override
	public <N2 extends Next, N1 extends Ent<N2, TInt>, N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> opForInt(Emitter<N0> em, IntJitType type) {
		return Op.irem(em);
	}

	@Override
	public <N2 extends Next, N1 extends Ent<N2, TLong>, N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TLong>> opForLong(Emitter<N0> em, LongJitType type) {
		return Op.lrem(em);
	}

	@Override
	public <THIS extends JitCompiledPassage> Emitter<Bot> genRunMpInt(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitIntSRemOp op,
			MpIntJitType type, Scope scope) {
		return genMpDelegationToStaticMethod(em, gen, localThis, type, "mpIntSignedDivide", op, 1,
			TakeOut.LEFT, scope);
	}
}
