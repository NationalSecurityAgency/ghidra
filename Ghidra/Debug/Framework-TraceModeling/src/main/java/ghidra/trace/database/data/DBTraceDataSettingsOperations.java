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
package ghidra.trace.database.data;

import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;

import com.google.common.collect.Range;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.data.DBTraceDataSettingsAdapter.DBTraceSettingsEntry;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.model.map.TraceAddressSnapRangePropertyMapOperations;
import ghidra.util.LockHold;

public interface DBTraceDataSettingsOperations
		extends TraceAddressSnapRangePropertyMapOperations<DBTraceSettingsEntry> {

	static void assertKnownType(Object obj) {
		if (obj instanceof Long) {
			return;
		}
		if (obj instanceof String) {
			return;
		}
		if (obj instanceof byte[]) {
			return;
		}
		throw new IllegalArgumentException("Value is not a known settings type");
	}

	void makeWay(DBTraceSettingsEntry entry, Range<Long> span);

	ReadWriteLock getLock();

	default DBTraceSettingsEntry doGetExactEntry(Range<Long> lifespan, Address address,
			String name) {
		for (DBTraceSettingsEntry entry : reduce(TraceAddressSnapRangeQuery.at(address,
			DBTraceUtils.lowerEndpoint(lifespan))).values()) {
			if (!lifespan.equals(entry.getLifespan())) {
				continue;
			}
			if (!name.equals(entry.name)) {
				continue;
			}
			return entry;
		}
		return null;
	}

	default void doMakeWay(Range<Long> span, Address address, String name) {
		for (DBTraceSettingsEntry entry : reduce(TraceAddressSnapRangeQuery.intersecting(
			new AddressRangeImpl(address, address), span)).values()) {
			if (name == null || name.equals(entry.name)) {
				makeWay(entry, span);
			}
		}
	}

	default DBTraceSettingsEntry doExactOrNew(Range<Long> lifespan, Address address, String name) {
		DBTraceSettingsEntry exact = doGetExactEntry(lifespan, address, name);
		if (exact != null) {
			return exact;
		}
		doMakeWay(lifespan, address, name);
		DBTraceSettingsEntry entry = put(address, lifespan, null);
		entry.setName(name);
		return entry;
	}

	default DBTraceSettingsEntry doGetEntry(long snap, Address address, String name) {
		for (DBTraceSettingsEntry entry : reduce(
			TraceAddressSnapRangeQuery.at(address, snap)).values()) {
			if (!name.equals(entry.name)) {
				continue;
			}
			return entry;
		}
		return null;
	}

	default void setLong(Range<Long> lifespan, Address address, String name, long value) {
		try (LockHold hold = LockHold.lock(getLock().writeLock())) {
			doExactOrNew(lifespan, address, name).setLong(value);
		}
	}

	default Long getLong(long snap, Address address, String name) {
		try (LockHold hold = LockHold.lock(getLock().readLock())) {
			DBTraceSettingsEntry entry = doGetEntry(snap, address, name);
			return entry == null ? null : entry.getLong();
		}
	}

	default void setString(Range<Long> lifespan, Address address, String name, String value) {
		try (LockHold hold = LockHold.lock(getLock().writeLock())) {
			doExactOrNew(lifespan, address, name).setString(value);
		}
	}

	default String getString(long snap, Address address, String name) {
		try (LockHold hold = LockHold.lock(getLock().readLock())) {
			DBTraceSettingsEntry entry = doGetEntry(snap, address, name);
			return entry == null ? null : entry.getString();
		}
	}

	default void setBytes(Range<Long> lifespan, Address address, String name, byte[] value) {
		try (LockHold hold = LockHold.lock(getLock().writeLock())) {
			doExactOrNew(lifespan, address, name).setBytes(value);
		}
	}

	default byte[] getBytes(long snap, Address address, String name) {
		try (LockHold hold = LockHold.lock(getLock().readLock())) {
			DBTraceSettingsEntry entry = doGetEntry(snap, address, name);
			return entry == null ? null : entry.getBytes();
		}
	}

	default void setValue(Range<Long> lifespan, Address address, String name, Object value) {
		assertKnownType(value);
		try (LockHold hold = LockHold.lock(getLock().writeLock())) {
			doExactOrNew(lifespan, address, name).setValue(value);
		}
	}

	default Object getValue(long snap, Address address, String name) {
		try (LockHold hold = LockHold.lock(getLock().readLock())) {
			DBTraceSettingsEntry entry = doGetEntry(snap, address, name);
			return entry == null ? null : entry.getValue();
		}
	}

	default void clear(Range<Long> span, Address address, String name) {
		try (LockHold hold = LockHold.lock(getLock().writeLock())) {
			doMakeWay(span, address, name);
		}
	}

	default Collection<String> getSettingNames(Range<Long> lifespan, Address address) {
		List<String> result = new ArrayList<>();
		try (LockHold hold = LockHold.lock(getLock().readLock())) {
			for (DBTraceSettingsEntry entry : reduce(TraceAddressSnapRangeQuery.intersecting(
				new AddressRangeImpl(address, address), lifespan)).values()) {
				result.add(entry.name);
			}
			return result;
		}
	}

	default boolean isEmpty(Range<Long> lifespan, Address address) {
		try (LockHold hold = LockHold.lock(getLock().readLock())) {
			return reduce(TraceAddressSnapRangeQuery.intersecting(
				new AddressRangeImpl(address, address), lifespan)).isEmpty();
		}
	}
}
