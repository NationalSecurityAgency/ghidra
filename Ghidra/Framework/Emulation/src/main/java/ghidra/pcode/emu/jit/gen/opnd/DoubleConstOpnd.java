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
package ghidra.pcode.emu.jit.gen.opnd;

import ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.TDouble;

/**
 * A constant {@code double}
 */
record DoubleConstOpnd(double value, DoubleJitType type)
		implements ConstSimpleOpnd<TDouble, DoubleJitType> {

	@Override
	public String name() {
		return "const_double_%f".formatted(value).replace(".", "dot");
	}

	@Override
	public <N extends Next> Emitter<Ent<N, TDouble>> read(Emitter<N> em) {
		return em.emit(Op::ldc__d, value);
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TDouble>> SimpleOpndEm<TDouble, DoubleJitType, N1>
			write(Emitter<N0> em, Scope scope) {
		return DoubleLocalOpnd.temp(type(), tempName(), scope).write(em, scope);
	}
}
