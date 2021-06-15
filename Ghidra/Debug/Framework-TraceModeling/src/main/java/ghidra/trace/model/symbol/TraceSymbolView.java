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

public interface TraceSymbolView<T extends TraceSymbol> {

	TraceSymbolManager getManager();

	default int size(boolean includeDynamicSymbols) {
		return getAll(includeDynamicSymbols).size();
	}

	Collection<? extends T> getAll(boolean includeDynamicSymbols);

	Collection<? extends T> getChildrenNamed(String name, TraceNamespaceSymbol parent);

	Collection<? extends T> getChildren(TraceNamespaceSymbol parent);

	default Collection<? extends T> getGlobalsNamed(String name) {
		return getChildrenNamed(name, getManager().getGlobalNamespace());
	}

	default Collection<? extends T> getGlobals() {
		return getChildren(getManager().getGlobalNamespace());
	}

	/**
	 * Get symbols with the given name, regardless of parent namespace
	 * 
	 * @param name the name
	 * @return the collection of symbols with the given name
	 */
	Collection<? extends T> getNamed(String name);

	/**
	 * Get symbols whose names match the given glob, regardless of parent namespace
	 * 
	 * @param glob the glob (* matches zero-or-more, ? matches one character)
	 * @param caseSensitive true to match case
	 * @return the collection of matching symbols
	 */
	Collection<? extends T> getWithMatchingName(String glob, boolean caseSensitive);
}
