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

import ghidra.pcode.emu.jit.analysis.JitType.IntJitType;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;

/**
 * A {@code int} local variable that cannot be used for temporary values
 * 
 * @see SimpleOpnd#ofIntReadOnly(IntJitType, Local)
 */
record IntReadOnlyLocalOpnd(IntJitType type, Local<TInt> local)
		implements LocalOpnd<TInt, IntJitType> {

	static IntReadOnlyLocalOpnd of(IntJitType type, Local<TInt> local) {
		return new IntReadOnlyLocalOpnd(type, local);
	}

	static IntReadOnlyLocalOpnd temp(IntJitType type, String name, Scope scope) {
		return of(type, scope.decl(type.bType(), name));
	}

	static <N1 extends Next, N0 extends Ent<N1, TInt>> SimpleOpndEm<TInt, IntJitType, N1>
			create(Emitter<N0> em, IntJitType type, String name, Scope scope) {
		IntReadOnlyLocalOpnd ro = IntReadOnlyLocalOpnd.temp(type, name, scope);
		return new SimpleOpndEm<>(ro, em.emit(Op::istore, ro.local));
	}

	@Override
	public <N extends Next> Emitter<Ent<N, TInt>> read(Emitter<N> em) {
		return em.emit(Op::iload, local);
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TInt>> SimpleOpndEm<TInt, IntJitType, N1>
			write(Emitter<N0> em, Scope scope) {
		String name = "%s_tempFromRo".formatted(this.name());
		return IntLocalOpnd.temp(type(), name, scope).write(em, scope);
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<N1> writeDirect(Emitter<N0> em) {
		throw new UnsupportedOperationException();
	}
}
