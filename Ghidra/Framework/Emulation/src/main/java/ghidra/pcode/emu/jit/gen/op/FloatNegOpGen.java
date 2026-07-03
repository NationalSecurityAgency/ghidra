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

import ghidra.pcode.emu.jit.gen.util.Emitter;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Op;
import ghidra.pcode.emu.jit.gen.util.Types.TDouble;
import ghidra.pcode.emu.jit.gen.util.Types.TFloat;
import ghidra.pcode.emu.jit.op.JitFloatNegOp;

/**
 * The generator for a {@link JitFloatNegOp float_neg}.
 * 
 * <p>
 * This uses the unary operator generator and emits {@link Op#fneg(Emitter) fneg} or
 * {@link Op#dneg(Emitter) dneg}.
 */
public enum FloatNegOpGen implements FloatOpUnOpGen<JitFloatNegOp> {
	/** The generator singleton */
	GEN;

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TFloat>> Emitter<Ent<N1, TFloat>>
			opForFloat(Emitter<N0> em) {
		return Op.fneg(em);
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TDouble>> Emitter<Ent<N1, TDouble>>
			opForDouble(Emitter<N0> em) {
		return Op.dneg(em);
	}
}
