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

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.symbol.TraceLabelSymbolView;
import ghidra.trace.model.symbol.TraceNamespaceSymbol;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.trace.util.TraceEvents;
import ghidra.util.LockHold;
import ghidra.util.exception.InvalidInputException;

public class DBTraceLabelSymbolView
		extends AbstractDBTraceSymbolSingleTypeWithLocationView<DBTraceLabelSymbol>
		implements TraceLabelSymbolView {

	public DBTraceLabelSymbolView(DBTraceSymbolManager manager) {
		super(manager, SymbolType.LABEL.getID(), manager.labelStore);
	}

	@Override
	public DBTraceLabelSymbol add(Lifespan lifespan, Address address, String name,
			TraceNamespaceSymbol parent, SourceType source)
			throws InvalidInputException, IllegalArgumentException {
		if (source == SourceType.DEFAULT) {
			throw new IllegalArgumentException();
		}
		DBTraceSymbolManager.assertValidName(name);
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			DBTraceNamespaceSymbol dbnsParent = manager.assertIsMine((Namespace) parent);
			DBTraceLabelSymbol label = store.create();
			label.set(lifespan, address, name, dbnsParent, source);
			manager.putID(lifespan, address, label.getID());

			cacheForAt.notifyNewEntry(lifespan, address, label);

			manager.trace.setChanged(new TraceChangeRecord<>(TraceEvents.SYMBOL_ADDED,
				label.getAddressSpace(), label));
			return label;
		}
	}
}
