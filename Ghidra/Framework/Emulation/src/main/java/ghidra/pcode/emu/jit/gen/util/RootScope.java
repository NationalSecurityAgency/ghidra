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
package ghidra.pcode.emu.jit.gen.util;

import java.util.ArrayList;
import java.util.List;

import ghidra.pcode.emu.jit.gen.util.Emitter.Bot;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.BNonVoid;

/**
 * The implementation of the root scope for local variable declarations
 * 
 * @param <N> the stack at scope start and finish (not really enforced). This should be {@link Bot}
 *            for the actual root scope, but this class is extended by {@link ChildScope}.
 */
class RootScope<N extends Next> implements Scope {
	protected final Emitter<N> em;
	protected final Lbl<N> start;

	protected int nextLocal;
	protected Scope childScope;
	protected boolean closed = false;

	protected final List<Local<?>> vars = new ArrayList<>();

	@SuppressWarnings("unchecked")
	RootScope(Emitter<?> em, int nextLocal) {
		this.em = (Emitter<N>) em;
		this.nextLocal = nextLocal;

		this.start = Lbl.place(this.em).lbl();
	}

	@Override
	public SubScope sub() {
		return new ChildScope<>(em, this);
	}

	protected void declVars() {
		var end = em.emit(Lbl::place).lbl();
		for (Local<?> v : vars) {
			em.emit(Local::decl, v, start, end);
		}
	}

	@Override
	public <T extends BNonVoid> Local<T> decl(T type, String name) {
		if (childScope != null) {
			throw new IllegalStateException("There is a child scope active.");
		}
		int next = next(type);
		Local<T> local = Local.of(type, name, next);
		vars.add(local);
		return local;
	}

	protected int next(BNonVoid type) {
		int next = nextLocal;
		nextLocal += type.slots();
		return next;
	}

	@Override
	public void close() {
		if (closed) {
			return;
		}
		declVars();
		closed = true;
	}
}
