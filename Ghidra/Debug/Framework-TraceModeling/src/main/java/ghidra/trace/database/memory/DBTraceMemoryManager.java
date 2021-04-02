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
package ghidra.trace.database.memory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.Predicate;

import com.google.common.collect.Collections2;
import com.google.common.collect.Range;

import db.DBHandle;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager;
import ghidra.trace.database.space.DBTraceDelegatingManager;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.MathUtilities;
import ghidra.util.UnionAddressSetView;
import ghidra.util.database.DBOpenMode;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class DBTraceMemoryManager
		extends AbstractDBTraceSpaceBasedManager<DBTraceMemorySpace, DBTraceMemoryRegisterSpace>
		implements TraceMemoryManager, DBTraceDelegatingManager<DBTraceMemorySpace> {
	protected static final String NAME = "Memory";

	public DBTraceMemoryManager(DBHandle dbh, DBOpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, Language baseLanguage, DBTrace trace,
			DBTraceThreadManager threadManager) throws IOException, VersionException {
		super(NAME, dbh, openMode, lock, monitor, baseLanguage, trace, threadManager);

		loadSpaces();
	}

	@Override
	protected DBTraceMemorySpace createSpace(AddressSpace space, DBTraceSpaceEntry ent)
			throws VersionException, IOException {
		return new DBTraceMemorySpace(this, dbh, space, ent);
	}

	@Override
	protected DBTraceMemoryRegisterSpace createRegisterSpace(AddressSpace space,
			DBTraceThread thread, DBTraceSpaceEntry ent) throws VersionException, IOException {
		return new DBTraceMemoryRegisterSpace(this, dbh, space, ent, thread);
	}

	@Override
	public DBTraceMemorySpace getForSpace(AddressSpace space, boolean createIfAbsent) {
		return super.getForSpace(space, createIfAbsent);
	}

	@Override
	public Lock readLock() {
		return lock.readLock();
	}

	@Override
	public Lock writeLock() {
		return lock.writeLock();
	}

	@Override
	public DBTraceMemorySpace getMemorySpace(AddressSpace space, boolean createIfAbsent) {
		return getForSpace(space, createIfAbsent);
	}

	@Override
	public DBTraceMemoryRegisterSpace getMemoryRegisterSpace(TraceThread thread,
			boolean createIfAbsent) {
		return getForRegisterSpace(thread, 0, createIfAbsent);
	}

	@Override
	public TraceMemoryRegisterSpace getMemoryRegisterSpace(TraceThread thread, int frame,
			boolean createIfAbsent) {
		return getForRegisterSpace(thread, frame, createIfAbsent);
	}

	@Override
	public DBTraceMemoryRegisterSpace getMemoryRegisterSpace(TraceStackFrame frame,
			boolean createIfAbsent) {
		return getForRegisterSpace(frame, createIfAbsent);
	}

	@Override
	public DBTraceMemoryRegion addRegion(String path, Range<Long> lifespan,
			AddressRange range, Collection<TraceMemoryFlag> flags)
			throws TraceOverlappedRegionException, DuplicateNameException {
		try {
			return delegateWrite(range.getAddressSpace(),
				m -> m.addRegion(path, lifespan, range, flags));
		}
		catch (TraceOverlappedRegionException | DuplicateNameException e) {
			throw e;
		}
		catch (UsrException e) {
			throw new AssertionError(e); // Should never happen
		}
	}

	@Override
	public Collection<TraceMemoryRegion> getAllRegions() {
		return delegateCollection(getActiveMemorySpaces(), m -> m.getAllRegions());
	}

	// Internal
	public Collection<DBTraceMemoryRegion> getRegionsInternal() {
		return delegateCollection(getActiveMemorySpaces(), m -> m.regionMapSpace.values());
	}

	@Override
	public DBTraceMemoryRegion getLiveRegionByPath(long snap, String regionName) {
		// Not efficient, but I don't anticipate many regions
		return delegateFirst(getActiveMemorySpaces(), m -> m.getLiveRegionByPath(snap, regionName));
	}

	@Override
	public DBTraceMemoryRegion getRegionContaining(long snap, Address address) {
		return delegateRead(address.getAddressSpace(), m -> m.getRegionContaining(snap, address));
	}

	@Override
	public Collection<? extends DBTraceMemoryRegion> getRegionsIntersecting(Range<Long> lifespan,
			AddressRange range) {
		return delegateRead(range.getAddressSpace(), m -> m.getRegionsIntersecting(lifespan, range),
			Collections.emptyList());
	}

	@Override
	public Collection<? extends DBTraceMemoryRegion> getRegionsAtSnap(long snap) {
		return delegateCollection(memSpaces.values(), m -> m.getRegionsAtSnap(snap));
	}

	public Collection<TraceMemoryRegion> getRegionsWithPathInLifespan(Range<Long> lifespan,
			String regionPath) {
		// Not efficient, but I don't anticipate many regions
		Collection<TraceMemoryRegion> result = new HashSet<>();
		for (DBTraceMemorySpace m : getActiveMemorySpaces()) {
			for (TraceMemoryRegion region : m.getRegionsIntersecting(lifespan, new AddressRangeImpl(
				m.getAddressSpace().getMinAddress(), m.getAddressSpace().getMaxAddress()))) {
				if (regionPath.equals(region.getPath())) {
					result.add(region);
				}
			}
		}
		return Collections.unmodifiableCollection(result);
	}

	@Override
	public AddressSetView getRegionsAddressSet(long snap) {
		return new UnionAddressSetView(Collections2.transform(getActiveMemorySpaces(),
			m -> m.getRegionsAddressSet(snap)));
	}

	@Override
	public AddressSetView getRegionsAddressSetWith(long snap,
			Predicate<TraceMemoryRegion> predicate) {
		return new UnionAddressSetView(Collections2.transform(getActiveMemorySpaces(),
			m -> m.getRegionsAddressSetWith(snap, predicate)));
	}

	@Override
	public void setState(long snap, Address address, TraceMemoryState state) {
		delegateWriteV(address.getAddressSpace(), m -> m.setState(snap, address, state));
	}

	@Override
	public void setState(long snap, Address start, Address end, TraceMemoryState state) {
		delegateWriteV(start.getAddressSpace(), m -> m.setState(snap, start, end, state));
	}

	@Override
	public void setState(long snap, AddressRange range, TraceMemoryState state) {
		delegateWriteV(range.getAddressSpace(), m -> m.setState(snap, range, state));
	}

	@Override
	public void setState(long snap, AddressSetView set, TraceMemoryState state) {
		for (AddressRange range : set) {
			delegateWriteV(range.getAddressSpace(), m -> m.setState(snap, range, state));
		}
	}

	@Override
	public TraceMemoryState getState(long snap, Address address) {
		return delegateRead(address.getAddressSpace(), m -> m.getState(snap, address));
	}

	@Override
	public Entry<Long, TraceMemoryState> getViewState(long snap, Address address) {
		return delegateRead(address.getAddressSpace(), m -> m.getViewState(snap, address));
	}

	@Override
	public Entry<TraceAddressSnapRange, TraceMemoryState> getMostRecentStateEntry(long snap,
			Address address) {
		return delegateRead(address.getAddressSpace(),
			m -> m.getMostRecentStateEntry(snap, address));
	}

	@Override
	public Entry<TraceAddressSnapRange, TraceMemoryState> getViewMostRecentStateEntry(long snap,
			Address address) {
		return delegateRead(address.getAddressSpace(),
			m -> m.getViewMostRecentStateEntry(snap, address));
	}

	@Override
	public AddressSetView getAddressesWithState(long snap, AddressSetView set,
			Predicate<TraceMemoryState> predicate) {
		return delegateAddressSet(getActiveMemorySpaces(),
			m -> m.getAddressesWithState(snap, set, predicate));
	}

	@Override
	public AddressSetView getAddressesWithState(long snap, Predicate<TraceMemoryState> predicate) {
		return new UnionAddressSetView(Collections2.transform(getActiveMemorySpaces(),
			m -> m.getAddressesWithState(snap, predicate)));
	}

	@Override
	public AddressSetView getAddressesWithState(Range<Long> lifespan,
			Predicate<TraceMemoryState> predicate) {
		return new UnionAddressSetView(Collections2.transform(getActiveMemorySpaces(),
			m -> m.getAddressesWithState(lifespan, predicate)));
	}

	@Override
	public Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> getStates(long snap,
			AddressRange range) {
		return delegateRead(range.getAddressSpace(), m -> m.getStates(snap, range),
			Collections.emptyList());
	}

	@Override
	public Iterable<Entry<TraceAddressSnapRange, TraceMemoryState>> getMostRecentStates(
			TraceAddressSnapRange within) {
		return delegateRead(within.getRange().getAddressSpace(), m -> m.getMostRecentStates(within),
			Collections.emptyList());
	}

	@Override
	public int putBytes(long snap, Address start, ByteBuffer buf) {
		return delegateWriteI(start.getAddressSpace(), m -> m.putBytes(snap, start, buf));
	}

	@Override
	public int getBytes(long snap, Address start, ByteBuffer buf) {
		return delegateReadI(start.getAddressSpace(), m -> m.getBytes(snap, start, buf), () -> {
			Address max = start.getAddressSpace().getMaxAddress();
			int len = MathUtilities.unsignedMin(buf.remaining(), max.subtract(start));
			buf.position(buf.position() + len);
			return len;
		});
	}

	@Override
	public int getViewBytes(long snap, Address start, ByteBuffer buf) {
		return delegateReadI(start.getAddressSpace(), m -> m.getViewBytes(snap, start, buf), () -> {
			Address max = start.getAddressSpace().getMaxAddress();
			int len = MathUtilities.unsignedMin(buf.remaining(), max.subtract(start));
			buf.position(buf.position() + len);
			return len;
		});
	}

	@Override
	public void removeBytes(long snap, Address start, int len) {
		delegateDeleteV(start.getAddressSpace(), m -> m.removeBytes(snap, start, len));
	}

	@Override
	public Address findBytes(long snap, AddressRange range, ByteBuffer data, ByteBuffer mask,
			boolean forward, TaskMonitor monitor) {
		return delegateRead(range.getAddressSpace(),
			m -> m.findBytes(snap, range, data, mask, forward, monitor));
	}

	@Override
	public MemBuffer getBufferAt(long snap, Address start, ByteOrder byteOrder) {
		// TODO: if null, return buffer of limitless 0s?
		return delegateRead(start.getAddressSpace(), m -> m.getBufferAt(snap, start, byteOrder));
	}

	@Override
	public void pack() {
		delegateWriteAll(getActiveSpaces(), m -> m.pack());
	}

	@Override
	public Collection<? extends DBTraceMemoryRegion> getRegionsAdded(long from, long to) {
		if (from == to) {
			return Collections.emptySet();
		}
		Collection<DBTraceMemoryRegion> result = new ArrayList<>();
		for (DBTraceMemorySpace space : memSpaces.values()) {
			result.addAll(space.regionMapSpace
					.reduce(TraceAddressSnapRangeQuery.added(from, to, space.space))
					.values());
		}
		return result;
	}

	@Override
	public Collection<? extends DBTraceMemoryRegion> getRegionsRemoved(long from, long to) {
		if (from == to) {
			return Collections.emptySet();
		}
		Collection<DBTraceMemoryRegion> result = new ArrayList<>();
		for (DBTraceMemorySpace space : memSpaces.values()) {
			result.addAll(space.regionMapSpace
					.reduce(TraceAddressSnapRangeQuery.removed(from, to, space.space))
					.values());
		}
		return result;
	}

	@Override
	public Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> getStateChanges(long from,
			long to) {
		if (from == to) {
			return Collections.emptySet();
		}
		Range<Long> between = from < to ? Range.closed(from + 1, to) : Range.closed(to + 1, from);
		Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> result = new ArrayList<>();
		for (DBTraceMemorySpace space : memSpaces.values()) {
			AddressRange rng =
				new AddressRangeImpl(space.space.getMinAddress(), space.space.getMaxAddress());
			result.addAll(space.stateMapSpace
					.reduce(TraceAddressSnapRangeQuery.enclosed(rng, between))
					.entries());
		}
		return result;
	}
}
