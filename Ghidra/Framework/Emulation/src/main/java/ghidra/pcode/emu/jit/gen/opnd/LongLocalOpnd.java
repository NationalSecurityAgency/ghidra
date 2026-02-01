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
 * A {@code long} local variable
 */
record LongLocalOpnd(LongJitType type, Local<TLong> local)
		implements LocalOpnd<TLong, LongJitType> {

	static LongLocalOpnd of(LongJitType type, Local<TLong> local) {
		return new LongLocalOpnd(type, local);
	}

	static LongLocalOpnd temp(LongJitType type, String name, Scope scope) {
		return of(type, scope.decl(type.bType(), name));
	}

	static <N1 extends Next, N0 extends Ent<N1, TLong>> SimpleOpndEm<TLong, LongJitType, N1> create(
			Emitter<N0> em, LongJitType type, String name, Scope scope) {
		return temp(type, name, scope).write(em, scope);
	}

	@Override
	public <N extends Next> Emitter<Ent<N, TLong>> read(Emitter<N> em) {
		return em.emit(Op::lload, local);
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TLong>> Emitter<N1> writeDirect(Emitter<N0> em) {
		return em.emit(Op::lstore, local);
	}
}
