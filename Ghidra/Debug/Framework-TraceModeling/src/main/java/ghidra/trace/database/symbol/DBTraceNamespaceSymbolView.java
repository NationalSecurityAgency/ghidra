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

import ghidra.program.model.symbol.*;
import ghidra.trace.model.Trace.TraceSymbolChangeType;
import ghidra.trace.model.symbol.TraceNamespaceSymbol;
import ghidra.trace.model.symbol.TraceNamespaceSymbolView;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class DBTraceNamespaceSymbolView
		extends AbstractDBTraceSymbolSingleTypeView<DBTraceNamespaceSymbol>
		implements TraceNamespaceSymbolView {

	public DBTraceNamespaceSymbolView(DBTraceSymbolManager manager) {
		super(manager, SymbolType.NAMESPACE.getID(), manager.namespaceStore);
	}

	@Override
	public DBTraceNamespaceSymbol add(String name, TraceNamespaceSymbol parent, SourceType source)
			throws DuplicateNameException, InvalidInputException, IllegalArgumentException {
		if (source == SourceType.DEFAULT) {
			throw new IllegalArgumentException();
		}
		DBTraceSymbolManager.assertValidName(name);
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			DBTraceNamespaceSymbol dbnsParent = manager.assertIsMine((Namespace) parent);
			manager.assertUniqueName(name, dbnsParent);
			DBTraceNamespaceSymbol namespace = store.create();
			namespace.set(name, dbnsParent, source);
			manager.trace.setChanged(
				new TraceChangeRecord<>(TraceSymbolChangeType.ADDED, null, namespace));
			return namespace;
		}
	}

	@Override
	protected Collection<DBTraceNamespaceSymbol> constructView() {
		return Collections.unmodifiableCollection(store.asMap().tailMap(1L).values());
	}
}
