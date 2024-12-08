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
package ghidra.trace.model.symbol;

import ghidra.util.LockHold;

/**
 * A symbol view where names cannot be duplicated within the same parent namespace
 *
 * @param <T> the type of symbols in the view
 */
public interface TraceSymbolNoDuplicatesView<T extends TraceSymbol> extends TraceSymbolView<T> {

	/**
	 * Get the child of the given parent having the given name.
	 * 
	 * @param name the name of the symbol
	 * @param parent the parent namespace
	 * @return the symbol, or null
	 */
	default T getChildNamed(String name, TraceNamespaceSymbol parent) {
		try (LockHold hold = getManager().getTrace().lockRead()) {
			for (T symbol : getChildrenNamed(name, parent)) {
				return symbol;
			}
			return null;
		}
	}

	/**
	 * A shorthand for {@link #getChildNamed(String, TraceNamespaceSymbol)} where parent is the
	 * global namespace.
	 * 
	 * @param name the name of the symbol
	 * @return the symbol, or null
	 */
	default T getGlobalNamed(String name) {
		return getChildNamed(name, getManager().getGlobalNamespace());
	}
}
