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
package ghidra.trace.database.listing;

import java.util.Iterator;
import java.util.Map;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalNotification;
import com.google.common.collect.Iterators;
import com.google.common.collect.Range;

import ghidra.program.model.address.*;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.listing.TraceUndefinedDataView;
import ghidra.util.*;

public class DBTraceUndefinedDataView extends
		AbstractSingleDBTraceCodeUnitsView<UndefinedDBTraceData> implements TraceUndefinedDataView {

	protected final static int CACHE_MAX_SNAPS = 5;

	protected final DBTraceCodeManager manager;

	protected final Map<Long, CachedAddressSetView> cache = CacheBuilder.newBuilder()
			.removalListener(this::cacheEntryRemoved)
			.maximumSize(CACHE_MAX_SNAPS)
			.build()
			.asMap();

	public DBTraceUndefinedDataView(DBTraceCodeSpace space) {
		super(space);
		this.manager = space.manager;
	}

	private void cacheEntryRemoved(RemovalNotification<Long, CachedAddressSetView> rn) {
		// Nothing
	}

	protected UndefinedDBTraceData doCreateUnit(long snap, Address address) {
		space.assertInSpace(address);
		return manager.doCreateUndefinedUnit(snap, address, space.getThread(),
			space.getFrameLevel());
	}

	@Override
	public int size() {
		return 0;
	}

	protected AddressSetView doGetAddressSetView(long snap) {
		return cache.computeIfAbsent(snap,
			t -> new CachedAddressSetView(new DifferenceAddressSetView(new AddressSet(space.all),
				space.definedUnits.getAddressSetView(t))));
	}

	@Override
	public boolean containsAddress(long snap, Address address) {
		return doGetAddressSetView(snap).contains(address);
	}

	@Override
	public boolean coversRange(Range<Long> lifespan, AddressRange range) {
		return !space.definedUnits.intersectsRange(lifespan, range);
	}

	@Override
	public boolean intersectsRange(Range<Long> lifespan, AddressRange range) {
		return !space.definedUnits.coversRange(lifespan, range);
	}

	@Override
	public UndefinedDBTraceData getFloor(long snap, Address address) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			// TODO: Not particularly efficient....
			for (UndefinedDBTraceData u : get(snap, address, false)) {
				return u;
			}
			return null;
		}
	}

	@Override
	public UndefinedDBTraceData getContaining(long snap, Address address) {
		return getAt(snap, address); // Undefined all of size 1
	}

	@Override
	public UndefinedDBTraceData getAt(long snap, Address address) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			if (doGetAddressSetView(snap).contains(address)) {
				return doCreateUnit(snap, address);
			}
			return null;
		}
	}

	@Override
	public UndefinedDBTraceData getCeiling(long snap, Address address) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			// TODO: Not particularly efficient....
			for (UndefinedDBTraceData u : get(snap, address, true)) {
				return u;
			}
			return null;
		}
	}

	@Override
	public Iterable<? extends UndefinedDBTraceData> get(long snap, Address min, Address max,
			boolean forward) {
		Iterator<Address> ait =
			getAddressSetView(snap, new AddressRangeImpl(min, max)).getAddresses(forward);
		return () -> Iterators.transform(ait, a -> doCreateUnit(snap, a));
	}

	@Override
	public Iterable<? extends UndefinedDBTraceData> getIntersecting(TraceAddressSnapRange tasr) {
		Iterator<Iterator<? extends UndefinedDBTraceData>> itIt =
			Iterators.transform(DBTraceUtils.iterateSpan(tasr.getLifespan()),
				snap -> get(snap, tasr.getX1(), tasr.getX2(), true).iterator());
		return () -> Iterators.concat(itIt);
	}

	@Override
	public AddressSetView getAddressSetView(long snap, AddressRange within) {
		return new IntersectionAddressSetView(new AddressSet(within),
			doGetAddressSetView(snap));
	}

	public void invalidateCache() {
		cache.clear();
	}
}
