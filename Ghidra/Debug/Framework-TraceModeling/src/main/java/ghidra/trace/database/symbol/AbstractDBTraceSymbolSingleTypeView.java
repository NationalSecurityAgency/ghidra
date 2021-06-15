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

import java.util.Collection;
import java.util.Collections;
import java.util.function.Predicate;

import com.google.common.collect.Collections2;

import ghidra.program.model.symbol.Namespace;
import ghidra.trace.model.symbol.TraceNamespaceSymbol;
import ghidra.util.LockHold;
import ghidra.util.UserSearchUtils;
import ghidra.util.database.DBCachedObjectIndex;
import ghidra.util.database.DBCachedObjectStore;

public abstract class AbstractDBTraceSymbolSingleTypeView<T extends AbstractDBTraceSymbol> {

	protected final DBTraceSymbolManager manager;
	protected final byte typeID;
	protected final DBCachedObjectStore<T> store;

	protected final Collection<T> view;
	protected final DBCachedObjectIndex<Long, T> symbolsByParentID;
	protected final DBCachedObjectIndex<String, T> symbolsByName;

	public AbstractDBTraceSymbolSingleTypeView(DBTraceSymbolManager manager, byte typeID,
			DBCachedObjectStore<T> store) {
		this.manager = manager;
		this.typeID = typeID;
		this.store = store;

		this.view = constructView();
		this.symbolsByParentID = store.getIndex(long.class, AbstractDBTraceSymbol.PARENT_COLUMN);
		this.symbolsByName = store.getIndex(String.class, AbstractDBTraceSymbol.NAME_COLUMN);
	}

	protected Collection<T> constructView() {
		return Collections.unmodifiableCollection(store.asMap().values());
	}

	public DBTraceSymbolManager getManager() {
		return manager;
	}

	// TODO: A place to store/manager/generate/whatever dynamic symbols
	// TODO: Do I generate them, or am I given them?
	public Collection<? extends T> getAll(boolean includeDynamicSymbols) {
		return view;
	}

	public Collection<? extends T> getChildrenNamed(String name, TraceNamespaceSymbol parent) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			DBTraceNamespaceSymbol dbnsParent = manager.assertIsMine((Namespace) parent);
			return Collections.unmodifiableCollection(Collections2.filter(
				symbolsByParentID.get(dbnsParent.getID()), s -> name.equals(s.name)));
		}
	}

	public Collection<? extends T> getChildren(TraceNamespaceSymbol parent) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			DBTraceNamespaceSymbol dbnsParent = manager.assertIsMine((Namespace) parent);
			return Collections.unmodifiableCollection(symbolsByParentID.get(dbnsParent.getID()));
		}
	}

	public Collection<? extends T> getNamed(String name) {
		return Collections.unmodifiableCollection(symbolsByName.get(name));
	}

	public Collection<? extends T> getWithMatchingName(String glob, boolean caseSensitive) {
		Predicate<String> predicate =
			UserSearchUtils.createSearchPattern(glob, caseSensitive).asPredicate();
		return Collections2.filter(view, s -> predicate.test(s.name));
	}

	public T getByKey(long key) {
		return store.getObjectAt(key);
	}

	public void invalidateCache() {
		store.invalidateCache();
	}
}
