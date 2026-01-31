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

import static ghidra.pcode.emu.jit.gen.GenConsts.MDESC_$DOUBLE_UNOP;
import static ghidra.pcode.emu.jit.gen.GenConsts.T_MATH;

import ghidra.pcode.emu.jit.gen.util.Emitter;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Op;
import ghidra.pcode.emu.jit.gen.util.Types.TDouble;
import ghidra.pcode.emu.jit.gen.util.Types.TFloat;
import ghidra.pcode.emu.jit.op.JitFloatSqrtOp;

/**
 * The generator for a {@link JitFloatSqrtOp float_sqrt}.
 * 
 * <p>
 * This uses the unary operator generator and emits an invocation of {@link Math#sqrt(double)},
 * possibly surrounding it with conversions from and to float.
 */
public enum FloatSqrtOpGen implements FloatOpUnOpGen<JitFloatSqrtOp> {
	/** The generator singleton */
	GEN;

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TFloat>> Emitter<Ent<N1, TFloat>>
			opForFloat(Emitter<N0> em) {
		return em
				.emit(Op::f2d)
				.emit(this::opForDouble)
				.emit(Op::d2f);
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TDouble>> Emitter<Ent<N1, TDouble>>
			opForDouble(Emitter<N0> em) {
		return em
				.emit(Op::invokestatic, T_MATH, "sqrt", MDESC_$DOUBLE_UNOP, false)
				.step(Inv::takeArg)
				.step(Inv::ret);
	}
}
