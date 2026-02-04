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

import ghidra.pcode.emu.jit.analysis.JitType.LongJitType;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.TLong;

/**
 * A constant {@code long}
 */
record LongConstOpnd(long value, LongJitType type)
		implements ConstSimpleOpnd<TLong, LongJitType> {

	@Override
	public String name() {
		return "const_long_0x%x".formatted(value);
	}

	@Override
	public <N extends Next> Emitter<Ent<N, TLong>> read(Emitter<N> em) {
		return em.emit(Op::ldc__l, value);
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TLong>> SimpleOpndEm<TLong, LongJitType, N1>
			write(Emitter<N0> em, Scope scope) {
		return LongLocalOpnd.temp(type(), tempName(), scope).write(em, scope);
	}
}
