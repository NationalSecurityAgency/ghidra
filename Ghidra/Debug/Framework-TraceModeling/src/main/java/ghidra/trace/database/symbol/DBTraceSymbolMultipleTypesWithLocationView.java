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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapSpace;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.symbol.DBTraceSymbolManager.DBTraceSymbolIDEntry;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.symbol.TraceNamespaceSymbol;
import ghidra.trace.model.symbol.TraceSymbolWithLocationView;
import ghidra.util.LazyCollection;
import ghidra.util.LockHold;
import ghidra.util.database.spatial.rect.Rectangle2DDirection;

public class DBTraceSymbolMultipleTypesWithLocationView<T extends AbstractDBTraceSymbol>
		extends DBTraceSymbolMultipleTypesView<T> implements TraceSymbolWithLocationView<T> {

	public DBTraceSymbolMultipleTypesWithLocationView(DBTraceSymbolManager manager,
			Collection<? extends AbstractDBTraceSymbolSingleTypeWithLocationView<? extends T>> parts) {
		super(manager, parts);
	}

	@SafeVarargs
	public DBTraceSymbolMultipleTypesWithLocationView(DBTraceSymbolManager manager,
			AbstractDBTraceSymbolSingleTypeWithLocationView<? extends T>... parts) {
		super(manager, parts);
	}

	@SuppressWarnings("unchecked")
	protected Collection<? extends AbstractDBTraceSymbolSingleTypeWithLocationView<? extends T>> getParts() {
		return (Collection<? extends AbstractDBTraceSymbolSingleTypeWithLocationView<? extends T>>) parts;
	}

	@Override
	public T getChildWithNameAt(String name, long snap, Address address,
			TraceNamespaceSymbol parent) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			for (AbstractDBTraceSymbolSingleTypeWithLocationView<? extends T> p : getParts()) {
				T symbol = p.getChildWithNameAt(name, snap, address, parent);
				if (symbol != null) {
					return symbol;
				}
			}
			return null;
		}
	}

	@Override
	public Collection<? extends T> getAt(long snap, Address address,
			boolean includeDynamicSymbols) {
		return getParts().stream()
				.flatMap(p -> p.getAt(snap, address, includeDynamicSymbols).stream())
				.toList();
	}

	@Override
	public Collection<? extends T> getIntersecting(Lifespan span, AddressRange range,
			boolean includeDynamicSymbols, boolean forward) {
		// NOTE: Do not use Catenated collection, so that the order is by address.
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			DBTraceAddressSnapRangePropertyMapSpace<Long, DBTraceSymbolIDEntry> space =
				manager.idMap.get(range.getAddressSpace(), false);
			if (space == null) {
				return Collections.emptyList();
			}
			return new LazyCollection<>(() -> space
					.reduce(TraceAddressSnapRangeQuery.intersecting(range, span)
							.starting(
								forward ? Rectangle2DDirection.LEFTMOST
										: Rectangle2DDirection.RIGHTMOST))
					.orderedValues()
					.stream()
					.filter(s -> {
						byte tid = DBTraceSymbolManager.unpackTypeID(s);
						for (AbstractDBTraceSymbolSingleTypeView<? extends T> p : parts) {
							if (p.typeID == tid) {
								return true;
							}
						}
						return false;
					})
					.map(s -> {
						byte tid = DBTraceSymbolManager.unpackTypeID(s);
						for (AbstractDBTraceSymbolSingleTypeView<? extends T> p : parts) {
							if (p.typeID == tid) {
								return p.store.getObjectAt(DBTraceSymbolManager.unpackKey(s));
							}
						}
						throw new AssertionError(); // Was filtered above
					}));
		}
	}
}
