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

import ghidra.pcode.emu.jit.gen.util.Emitter;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Op;
import ghidra.pcode.emu.jit.gen.util.Types.TDouble;
import ghidra.pcode.emu.jit.gen.util.Types.TFloat;
import ghidra.pcode.emu.jit.op.JitFloatAbsOp;

/**
 * The generator for a {@link JitFloatAbsOp float_abs}.
 * 
 * <p>
 * This uses the unary operator generator and emits an invocation of {@link Math#abs(float)} or
 * {@link Math#abs(double)}, depending on the type.
 */
public enum FloatAbsOpGen implements FloatOpUnOpGen<JitFloatAbsOp> {
	/** The generator singleton */
	GEN;

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TFloat>> Emitter<Ent<N1, TFloat>>
			opForFloat(Emitter<N0> em) {
		return em
				.emit(Op::invokestatic, T_MATH, "abs", MDESC_$FLOAT_UNOP, false)
				.step(Inv::takeArg)
				.step(Inv::ret);
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TDouble>> Emitter<Ent<N1, TDouble>>
			opForDouble(Emitter<N0> em) {
		return em
				.emit(Op::invokestatic, T_MATH, "abs", MDESC_$DOUBLE_UNOP, false)
				.step(Inv::takeArg)
				.step(Inv::ret);
	}
}
