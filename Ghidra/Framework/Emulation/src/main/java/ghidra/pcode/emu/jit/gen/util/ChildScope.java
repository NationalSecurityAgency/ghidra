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

import ghidra.pcode.emu.jit.gen.util.Emitter.Next;

/**
 * The implementation of a child scope for local variable declarations
 * 
 * @param <N> the stack at scope start and finish (not really enforced)
 */
class ChildScope<N extends Next> extends RootScope<N> implements SubScope {
	protected final RootScope<N> parentScope;

	ChildScope(Emitter<? extends Next> em, RootScope<N> parentScope) {
		super(em, parentScope.nextLocal);
		this.parentScope = parentScope;
		parentScope.childScope = this;
	}

	@Override
	public void close() {
		super.close();
		parentScope.childScope = null;
	}
}
