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
package ghidra.trace.database.module;

import java.io.IOException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;

import db.DBHandle;
import ghidra.framework.data.OpenMode;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceManager;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.modules.TraceConflictedMappingException;
import ghidra.trace.model.modules.TraceStaticMappingManager;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.trace.util.TraceEvents;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceStaticMappingManager implements TraceStaticMappingManager, DBTraceManager {
	protected final DBHandle dbh;
	protected final ReadWriteLock lock;
	protected final DBTrace trace;
	protected final DBTraceOverlaySpaceAdapter overlayAdapter;

	// TODO: Why doesn't this use the R*-Tree-based store like the others?
	//       Perhaps I thought it was overkill.... Probably should change over.
	//       See DBTraceBookmarkManager for reference. Add DBTraceStaticMappingSpace.
	protected final DBCachedObjectStore<DBTraceStaticMapping> mappingStore;
	protected final DBCachedObjectIndex<Address, DBTraceStaticMapping> mappingsByAddress;
	protected final Collection<DBTraceStaticMapping> view;

	public DBTraceStaticMappingManager(DBHandle dbh, OpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, DBTrace trace, DBTraceOverlaySpaceAdapter overlayAdapter)
			throws VersionException, IOException {
		this.dbh = dbh;
		this.lock = lock;
		this.trace = trace;

		this.overlayAdapter = overlayAdapter;

		DBCachedObjectStoreFactory factory = trace.getStoreFactory();
		mappingStore = factory.getOrCreateCachedStore(DBTraceStaticMapping.TABLE_NAME,
			DBTraceStaticMapping.class, (s, r) -> new DBTraceStaticMapping(this, s, r), true);
		mappingsByAddress =
			mappingStore.getIndex(Address.class, DBTraceStaticMapping.TRACE_ADDRESS_COLUMN);
		view = Collections.unmodifiableCollection(mappingStore.asMap().values());
	}

	@Override
	public void invalidateCache(boolean all) {
		mappingStore.invalidateCache();
	}

	@Override
	public void dbError(IOException e) {
		trace.dbError(e);
	}

	@Override
	public DBTraceStaticMapping add(AddressRange range, Lifespan lifespan, URL toProgramURL,
			String toAddress) throws TraceConflictedMappingException {
		Objects.requireNonNull(toProgramURL,
			"Program URL cannot be null. Program must be in a project to have a URL.");
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			DBTraceStaticMapping conflict =
				findAnyConflicting(range, lifespan, toProgramURL, toAddress);
			if (conflict != null) {
				// TODO: Find all conflicts?
				throw new TraceConflictedMappingException("Another mapping would conflict",
					Set.of(conflict));
			}
			// TODO: A more sophisticated coverage check?
			// TODO: Better coalescing
			// For now, just check if a single entry contains the would-be-new entry
			for (DBTraceStaticMapping covers : findAllOverlapping(range, lifespan)) {
				if (!covers.getTraceAddressRange().contains(range.getMinAddress())) {
					continue;
				}
				if (!covers.getTraceAddressRange().contains(range.getMaxAddress())) {
					continue;
				}
				if (!covers.getLifespan().encloses(lifespan)) {
					continue;
				}
				return covers;
			}
			DBTraceStaticMapping mapping = mappingStore.create();
			mapping.set(range, lifespan, toProgramURL, toAddress);
			trace.setChanged(new TraceChangeRecord<>(TraceEvents.MAPPING_ADDED,
				range.getAddressSpace(), mapping));
			return mapping;
		}
	}

	@Override
	public Collection<? extends DBTraceStaticMapping> getAllEntries() {
		return view;
	}

	@Override
	public DBTraceStaticMapping findContaining(Address address, long snap) {
		for (DBTraceStaticMapping mapping : mappingsByAddress.head(address, true)
				.descending()
				.values()) {
			if (!mapping.getLifespan().contains(snap)) {
				continue;
			}
			if (!mapping.getTraceAddressRange().contains(address)) {
				break; // None before can overlap
			}
			return mapping;
		}
		return null;
	}

	@Override
	public DBTraceStaticMapping findAnyConflicting(AddressRange range, Lifespan lifespan,
			URL toProgramURL, String toAddress) {
		for (DBTraceStaticMapping mapping : mappingsByAddress.head(range.getMaxAddress(), true)
				.descending()
				.values()) {
			if (!mapping.conflictsWith(range, lifespan, toProgramURL, toAddress)) {
				continue;
			}
			if (!mapping.getTraceAddressRange().intersects(range)) {
				if (mapping.getLifespan().encloses(lifespan)) {
					break;
				}
				continue;
			}
			return mapping;
		}
		return null;
	}

	@Override
	public Collection<? extends DBTraceStaticMapping> findAllOverlapping(AddressRange range,
			Lifespan lifespan) {
		Set<DBTraceStaticMapping> result = new HashSet<>();
		for (DBTraceStaticMapping mapping : mappingsByAddress.head(range.getMaxAddress(), true)
				.descending()
				.values()) {
			if (!mapping.getLifespan().intersects(lifespan)) {
				continue;
			}
			if (!mapping.getTraceAddressRange().intersects(range)) {
				if (mapping.getLifespan().encloses(lifespan)) {
					break;
				}
				continue;
			}
			result.add(mapping);
		}
		return result;
	}

	public void delete(DBTraceStaticMapping mapping) {
		mappingStore.delete(mapping);
		trace.setChanged(new TraceChangeRecord<>(TraceEvents.MAPPING_DELETED,
			mapping.getTraceAddressRange().getAddressSpace(), mapping));
	}
}
