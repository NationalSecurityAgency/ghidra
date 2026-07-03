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
import ghidra.pcode.emu.jit.gen.util.Lbl.LblEm;
import ghidra.pcode.emu.jit.gen.util.Op;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.op.JitFloatEqualOp;

/**
 * The generator for a {@link JitFloatEqualOp float_equal}.
 * 
 * <p>
 * This uses the float comparison operator generator and simply emits {@link Op#fcmpl(Emitter)
 * fcmpl} or {@link Op#dcmpl(Emitter) dcmpl} depending on the type and then {@link Op#ifeq(Emitter)
 * ifeq}.
 */
public enum FloatEqualOpGen implements FloatCompareBinOpGen<JitFloatEqualOp> {
	/** The generator singleton */
	GEN;

	@Override
	public <N2 extends Next, N1 extends Ent<N2, TFloat>, N0 extends Ent<N1, TFloat>> //
			Emitter<Ent<N2, TInt>> opForFloatCmp(Emitter<N0> em) {
		return Op.fcmpl(em);
	}

	@Override
	public <N2 extends Next, N1 extends Ent<N2, TDouble>, N0 extends Ent<N1, TDouble>> //
			Emitter<Ent<N2, TInt>> opForDoubleCmp(Emitter<N0> em) {
		return Op.dcmpl(em);
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TInt>> LblEm<N1, N1> opForCondJump(Emitter<N0> em) {
		return Op.ifeq(em);
	}
}
