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

import java.util.Collection;
import java.util.Iterator;

/**
 * A type-specific view in the trace symbol table
 *
 * <p>
 * The sub-interfaces of this handle the nuances for symbol types with more capabilities and/or
 * restrictions.
 *
 * @param <T> the type of symbols in the view
 */
public interface TraceSymbolView<T extends TraceSymbol> {

	/**
	 * Get the symbol manager for the trace.
	 * 
	 * @return the symbol manager
	 */
	TraceSymbolManager getManager();

	/**
	 * Get the number of symbols in this view.
	 * 
	 * @param includeDynamicSymbols true to include dynamically-generated symbols
	 * @return the number of symbols
	 */
	default int size(boolean includeDynamicSymbols) {
		return getAll(includeDynamicSymbols).size();
	}

	/**
	 * Get all the symbols in this view.
	 * 
	 * @param includeDynamicSymbols true to include dynamically-generated symbols
	 * @return the symbols in this view satisfying the query
	 */
	Collection<? extends T> getAll(boolean includeDynamicSymbols);

	/**
	 * Get all children of the given parent namespace having the given name in this view.
	 * 
	 * @param name the name of the symbols
	 * @param parent the parent namespace
	 * @return the symbols in this view satisfying the query
	 */
	Collection<? extends T> getChildrenNamed(String name, TraceNamespaceSymbol parent);

	/**
	 * Get all children of the given parent namespace in this view.
	 * 
	 * @param parent the parent namespace
	 * @return the symbols in this view satisfying the query
	 */
	Collection<? extends T> getChildren(TraceNamespaceSymbol parent);

	/**
	 * A shorthand for {@link #getChildrenNamed(String, TraceNamespaceSymbol)} where parent is the
	 * global namespace.
	 * 
	 * @param name the name of the symbols
	 * @return the symbols in this view satisfying the query
	 */
	default Collection<? extends T> getGlobalsNamed(String name) {
		return getChildrenNamed(name, getManager().getGlobalNamespace());
	}

	/**
	 * A shorthand for {@link #getChildren(TraceNamespaceSymbol)} where parent is the global
	 * namespace.
	 * 
	 * @return the symbols in this view satisfying the query
	 */
	default Collection<? extends T> getGlobals() {
		return getChildren(getManager().getGlobalNamespace());
	}

	/**
	 * Get symbols in this view with the given name, regardless of parent namespace
	 * 
	 * @param name the name of the symbols
	 * @return the symbols in this view satisfying the query
	 */
	Collection<? extends T> getNamed(String name);

	/**
	 * Get symbols in this view whose names match the given glob, regardless of parent namespace
	 * 
	 * @param glob the glob (* matches zero-or-more, ? matches one character)
	 * @param caseSensitive true to match case
	 * @return the symbols in this view satisfying the query
	 */
	Collection<? extends T> getWithMatchingName(String glob, boolean caseSensitive);

	/**
	 * Scan symbols in this view lexicographically by name starting at the given lower bound
	 * 
	 * @param startName the starting lower bound
	 * @return an iterator over symbols in this view satisfying the query
	 */
	Iterator<? extends T> scanByName(String startName);
}
