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

import ghidra.pcode.emu.jit.gen.util.Types.BNonVoid;

/**
 * A scope for local variable declarations, but not treated as a resource
 */
public interface Scope {

	/**
	 * Open a child scope of this scope, usually for temporary declarations/allocations
	 * <p>
	 * The variables declared in this scope (see {@link #decl(BNonVoid, String)}) are reserved only
	 * with the scope of the {@code try-with-resources} block that ought to be used to managed this
	 * resource. Local variables meant to be in scope for the method's full scope should just be
	 * declared in the {@linkplain Emitter#rootScope() root scope}.
	 * 
	 * @return the child scope
	 */
	SubScope sub();

	/**
	 * Declare a local variable in this scope
	 * <p>
	 * This assigns the local the next available index, being careful to increment the index
	 * according to the category of the given type. When this scope is closed, that index is reset
	 * to what is was at the start of this scope.
	 * 
	 * @param <T> the type of the variable
	 * @param type the type of the variable
	 * @param name the name of the variable
	 * @return the handle to the variable
	 */
	<T extends BNonVoid> Local<T> decl(T type, String name);

	/**
	 * Close this scope
	 * <p>
	 * This resets the index to what it was at the start of this scope. In general, there is no need
	 * for the user to call this on the root scope. This is automatically done by
	 * {@link Misc#finish(Emitter)}.
	 */
	void close();
}
