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

import com.google.common.collect.Collections2;
import com.google.common.collect.Range;

import generic.CatenatedCollection;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapSpace;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.DBTraceSpaceKey;
import ghidra.trace.database.symbol.DBTraceSymbolManager.DBTraceSymbolIDEntry;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.symbol.TraceNamespaceSymbol;
import ghidra.trace.model.symbol.TraceSymbolWithLocationView;
import ghidra.trace.model.thread.TraceThread;
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
	public T getChildWithNameAt(String name, long snap, TraceThread thread, Address address,
			TraceNamespaceSymbol parent) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			for (AbstractDBTraceSymbolSingleTypeWithLocationView<? extends T> p : getParts()) {
				T symbol = p.getChildWithNameAt(name, snap, thread, address, parent);
				if (symbol != null) {
					return symbol;
				}
			}
			return null;
		}
	}

	@Override
	public Collection<? extends T> getAt(long snap, TraceThread thread, Address address,
			boolean includeDynamicSymbols) {
		return new CatenatedCollection<>(Collections2.transform(getParts(),
			p -> p.getAt(snap, thread, address, includeDynamicSymbols)));
	}

	@Override
	public Collection<? extends T> getIntersecting(Range<Long> span, TraceThread thread,
			AddressRange range, boolean includeDynamicSymbols, boolean forward) {
		// NOTE: Do not use Catenated collection, so that the order is by address.
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			DBTraceThread dbThread =
				thread == null ? null : manager.trace.getThreadManager().assertIsMine(thread);
			manager.assertValidThreadAddress(dbThread, range.getMinAddress()); // Only examines space
			DBTraceAddressSnapRangePropertyMapSpace<Long, DBTraceSymbolIDEntry> space =
				manager.idMap.get(DBTraceSpaceKey.create(range.getAddressSpace(), dbThread, 0),
					false);
			if (space == null) {
				return Collections.emptyList();
			}
			Collection<Long> sids =
				space.reduce(TraceAddressSnapRangeQuery.intersecting(range, span)
						.starting(
							forward ? Rectangle2DDirection.LEFTMOST
									: Rectangle2DDirection.RIGHTMOST))
						.orderedValues();
			Collection<Long> matchingTid = Collections2.filter(sids, s -> {
				byte tid = DBTraceSymbolManager.unpackTypeID(s);
				for (AbstractDBTraceSymbolSingleTypeView<? extends T> p : parts) {
					if (p.typeID == tid) {
						return true;
					}
				}
				return false;
			});
			return Collections2.transform(matchingTid, s -> {
				byte tid = DBTraceSymbolManager.unpackTypeID(s);
				for (AbstractDBTraceSymbolSingleTypeView<? extends T> p : parts) {
					if (p.typeID == tid) {
						return p.store.getObjectAt(DBTraceSymbolManager.unpackKey(s));
					}
				}
				throw new AssertionError(); // Was filtered above
			});
		}
	}
}
