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

import java.util.ArrayList;
import java.util.List;

import ghidra.pcode.emu.jit.analysis.JitType.IntJitType;
import ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.MpIntLocalOpnd;
import ghidra.pcode.emu.jit.gen.opnd.SimpleOpnd;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.op.JitIntNegateOp;

/**
 * The generator for a {@link JitIntNegateOp int_negate}.
 * <p>
 * There is no bitwise "not" operator in the JVM. We borrow the pattern we see output by the Java
 * compiler for <code>int negate(n) {return ~n;}</code>. It XORs the input with a register of 1s.
 * This uses the unary operator generator and emits the equivalent code.
 */
public enum IntNegateOpGen implements IntOpUnOpGen<JitIntNegateOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return false; // TODO: Is it? Test with 3-byte operands to figure it out.
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<Ent<N1, TInt>>
			opForInt(Emitter<N0> em) {
		return em
				.emit(Op::ldc__i, -1)
				.emit(Op::ixor);
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TLong>> Emitter<Ent<N1, TLong>>
			opForLong(Emitter<N0> em) {
		return em
				.emit(Op::ldc__l, -1L)
				.emit(Op::lxor);
	}

	@Override
	public <THIS extends JitCompiledPassage> Emitter<Bot> genRunMpInt(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitIntNegateOp op,
			MpIntJitType type, Scope scope) {
		var opnd = gen.genReadToOpnd(em, localThis, op.u(), type, ext(), scope);
		em = opnd.em();
		var legs = opnd.opnd().type().castLegsLE(opnd.opnd());

		List<SimpleOpnd<TInt, IntJitType>> outLegs = new ArrayList<>();
		int legCount = type.legsAlloc();
		for (int i = 0; i < legCount; i++) {
			var result = em
					.emit(legs.get(i)::read)
					.emit(this::opForInt)
					.emit(legs.get(i)::write, scope);
			em = result.em();
			outLegs.add(result.opnd());
		}
		var out = MpIntLocalOpnd.of(type, "out", outLegs);
		return gen.genWriteFromOpnd(em, localThis, op.out(), out, ext(), scope);
	}
}
