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
import ghidra.pcode.emu.jit.op.JitIntMultOp;

/**
 * The generator for a {@link JitIntMultOp int_mult}.
 * 
 * <p>
 * This uses the binary operator generator and simply emits {@link Op#imul(Emitter) imul} or
 * {@link Op#lmul(Emitter) lmul} depending on the type.
 * <p>
 * For multi-precision multiplication, this emits code to invoke
 * {@link JitCompiledPassage#mpIntMultiply(int[], int[], int[])}
 */
public enum IntMultOpGen implements IntOpBinOpGen<JitIntMultOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return false;
	}

	@Override
	public <N2 extends Next, N1 extends Ent<N2, TInt>, N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> opForInt(Emitter<N0> em, IntJitType type) {
		return Op.imul(em);
	}

	@Override
	public <N2 extends Next, N1 extends Ent<N2, TLong>, N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TLong>> opForLong(Emitter<N0> em, LongJitType type) {
		return Op.lmul(em);
	}

	/**
	 * Generate the mp-int multiply code.
	 * <p>
	 * <b>NOTE:</b> I'd really like to know how many legs of the input operands are actually
	 * relevant. Very often, the following idiom is used:
	 * 
	 * <pre>
	 * temp: 16 = zext(r1) * zext(r2);
	 * r0 = temp(0);
	 * </pre>
	 * <p>
	 * That ensures all the operand sizes match, which is often (at least conventionally) required
	 * by the Sleigh compiler. However, if r1 and r2 are each only 64 bits, and I can keep track of
	 * that fact, then I could perform about half as many multiplies and adds. It also be nice if I
	 * can look ahead and see that only 64 bits of temp is actually used. The same is true of
	 * {@link IntDivOpGen}, {@link IntRemOpGen}, {@link IntSDivOpGen}, and {@link IntSRemOpGen}.
	 * <p>
	 * <b>IDEA:</b> It would be quite a change, but perhaps generating a temporary JVM-level DFG
	 * would be useful for culling. The difficulty here is knowing whether or not a temp (unique) is
	 * used by a later cross-build. Maybe with the right API calls, I could derive that without
	 * additional Sleigh compiler support. If used, I should not cull any computations, so that the
	 * retired value is the full value.
	 * 
	 * @param em the code emitter with an empty stack
	 * @param localThis a handle to the owning compiled passage
	 * @param gen the code generator
	 * @param op the p-code op
	 * @param type the (uniform) type of the inputs and output operands
	 * @param scope a scope for op-temporary variables
	 */
	@Override
	public <THIS extends JitCompiledPassage> Emitter<Bot> genRunMpInt(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitIntMultOp op,
			MpIntJitType type, Scope scope) {
		return genMpDelegationToStaticMethod(em, gen, localThis, type, "mpIntMultiply", op, 0,
			TakeOut.OUT, scope);
	}
}
