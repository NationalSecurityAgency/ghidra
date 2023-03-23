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
package ghidra.trace.database.symbol;

import java.util.*;
import java.util.stream.Collectors;

import ghidra.trace.model.symbol.*;
import ghidra.util.LazyCollection;
import ghidra.util.MergeSortingIterator;

public class DBTraceSymbolMultipleTypesView<T extends AbstractDBTraceSymbol>
		implements TraceSymbolView<T> {

	protected final DBTraceSymbolManager manager;
	protected final Collection<? extends AbstractDBTraceSymbolSingleTypeView<? extends T>> parts;

	public DBTraceSymbolMultipleTypesView(DBTraceSymbolManager manager,
			Collection<? extends AbstractDBTraceSymbolSingleTypeView<? extends T>> parts) {
		this.manager = manager;
		this.parts = parts;
	}

	@Override
	public TraceSymbolManager getManager() {
		return manager;
	}

	@SafeVarargs
	public DBTraceSymbolMultipleTypesView(DBTraceSymbolManager manager,
			AbstractDBTraceSymbolSingleTypeView<? extends T>... parts) {
		this(manager, Arrays.asList(parts));
	}

	@Override
	public Collection<? extends T> getAll(boolean includeDynamicSymbols) {
		return new LazyCollection<>(
			() -> parts.stream().flatMap(p -> p.getAll(includeDynamicSymbols).stream()));
	}

	@Override
	public Collection<? extends T> getChildrenNamed(String name, TraceNamespaceSymbol parent) {
		return parts.stream().flatMap(p -> p.getChildrenNamed(name, parent).stream()).toList();
	}

	@Override
	public Collection<? extends T> getChildren(TraceNamespaceSymbol parent) {
		return new LazyCollection<>(
			() -> parts.stream().flatMap(p -> p.getChildren(parent).stream()));
	}

	@Override
	public Collection<? extends T> getNamed(String name) {
		return parts.stream().flatMap(p -> p.getNamed(name).stream()).toList();
	}

	@Override
	public Collection<? extends T> getWithMatchingName(String glob, boolean caseSensitive) {
		return new LazyCollection<>(() -> parts.stream()
				.flatMap(p -> p.getWithMatchingName(glob, caseSensitive).stream()));
	}

	@Override
	public Iterator<? extends T> scanByName(String startName) {
		List<Iterator<? extends T>> iterators =
			parts.stream().map(p -> p.scanByName(startName)).collect(Collectors.toList());
		return new MergeSortingIterator<>(iterators, Comparator.comparing(s -> s.getName()));
	}
}
