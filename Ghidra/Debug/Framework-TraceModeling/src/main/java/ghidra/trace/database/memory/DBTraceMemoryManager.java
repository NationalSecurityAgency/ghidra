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

import db.DBHandle;
import ghidra.framework.data.OpenMode;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager;
import ghidra.trace.database.space.DBTraceDelegatingManager;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.MathUtilities;
import ghidra.util.UnionAddressSetView;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceMemoryManager extends AbstractDBTraceSpaceBasedManager<DBTraceMemorySpace>
		implements TraceMemoryManager, InternalTraceMemoryOperations,
		DBTraceDelegatingManager<DBTraceMemorySpace> {

	protected static final String NAME = "Memory";

	protected final DBTraceOverlaySpaceAdapter overlayAdapter;

	public DBTraceMemoryManager(DBHandle dbh, OpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, Language baseLanguage, DBTrace trace,
			DBTraceThreadManager threadManager, DBTraceOverlaySpaceAdapter overlayAdapter)
			throws IOException, VersionException {
		super(NAME, dbh, openMode, lock, monitor, baseLanguage, trace, threadManager);
		this.overlayAdapter = overlayAdapter;

		loadSpaces();
	}

	@Override
	public AddressSpace getSpace() {
		return null;
	}

	@Override
	public AddressSpace createOverlayAddressSpace(String name, AddressSpace base)
			throws DuplicateNameException {
		return overlayAdapter.createOverlayAddressSpace(name, base);
	}

	@Override
	public AddressSpace getOrCreateOverlayAddressSpace(String name, AddressSpace base) {
		return overlayAdapter.getOrCreateOverlayAddressSpace(name, base);
	}

	@Override
	public void deleteOverlayAddressSpace(String name) {
		overlayAdapter.deleteOverlayAddressSpace(name);
	}

	@Override
	protected DBTraceMemorySpace createSpace(AddressSpace space, DBTraceSpaceEntry ent)
			throws VersionException, IOException {
		return new DBTraceMemorySpace(this, dbh, space, ent);
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
	public DBTraceMemorySpace getMemoryRegisterSpace(TraceThread thread, boolean createIfAbsent) {
		return getForRegisterSpace(thread, 0, createIfAbsent);
	}

	@Override
	public DBTraceMemorySpace getMemoryRegisterSpace(TraceThread thread, int frame,
			boolean createIfAbsent) {
		return getForRegisterSpace(thread, frame, createIfAbsent);
	}

	@Override
	public DBTraceMemorySpace getMemoryRegisterSpace(TraceStackFrame frame,
			boolean createIfAbsent) {
		return getForRegisterSpace(frame, createIfAbsent);
	}

	@Override
	public TraceMemoryRegion addRegion(String path, Lifespan lifespan, AddressRange range,
			Collection<TraceMemoryFlag> flags) throws TraceOverlappedRegionException {
		return trace.getObjectManager().addMemoryRegion(path, lifespan, range, flags);
	}

	@Override
	public Collection<? extends TraceMemoryRegion> getAllRegions() {
		return trace.getObjectManager().getAllObjects(TraceMemoryRegion.class);
	}

	@Override
	public TraceMemoryRegion getLiveRegionByPath(long snap, String path) {
		return trace.getObjectManager().getObjectByPath(snap, path, TraceMemoryRegion.class);
	}

	@Override
	public TraceMemoryRegion getRegionContaining(long snap, Address address) {
		return trace.getObjectManager()
				.getObjectContaining(snap, address, TraceMemoryRegion.KEY_RANGE,
					TraceMemoryRegion.class);
	}

	@Override
	public Collection<? extends TraceMemoryRegion> getRegionsIntersecting(Lifespan lifespan,
			AddressRange range) {
		return trace.getObjectManager()
				.getObjectsIntersecting(lifespan, range, TraceMemoryRegion.KEY_RANGE,
					TraceMemoryRegion.class);
	}

	@Override
	public Collection<? extends TraceMemoryRegion> getRegionsAtSnap(long snap) {
		return trace.getObjectManager().getObjectsAtSnap(snap, TraceMemoryRegion.class);
	}

	@Override
	public AddressSetView getRegionsAddressSet(long snap) {
		return trace.getObjectManager()
				.getObjectsAddressSet(snap, TraceMemoryRegion.KEY_RANGE,
					TraceMemoryRegion.class, r -> true);
	}

	@Override
	public AddressSetView getRegionsAddressSetWith(long snap,
			Predicate<TraceMemoryRegion> predicate) {
		return trace.getObjectManager()
				.getObjectsAddressSet(snap, TraceMemoryRegion.KEY_RANGE,
					TraceMemoryRegion.class, predicate);
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
		return delegateReadOr(address.getAddressSpace(), m -> m.getViewState(snap, address),
			() -> Map.entry(snap, TraceMemoryState.UNKNOWN));
	}

	@Override
	public Entry<TraceAddressSnapRange, TraceMemoryState> getMostRecentStateEntry(long snap,
			Address address) {
		return delegateRead(address.getAddressSpace(),
			m -> m.getMostRecentStateEntry(snap, address));
	}

	@Override
	public Entry<TraceAddressSnapRange, TraceMemoryState> getViewMostRecentStateEntry(long snap,
			AddressRange range, Predicate<TraceMemoryState> predicate) {
		return delegateRead(range.getAddressSpace(),
			m -> m.getViewMostRecentStateEntry(snap, range, predicate));
	}

	@Override
	public Entry<TraceAddressSnapRange, TraceMemoryState> getViewMostRecentStateEntry(long snap,
			Address address) {
		return delegateRead(address.getAddressSpace(),
			m -> m.getViewMostRecentStateEntry(snap, address));
	}

	@Override
	public AddressSetView getAddressesWithState(Lifespan snap, AddressSetView set,
			Predicate<TraceMemoryState> predicate) {
		return delegateAddressSet(getActiveSpaces(),
			m -> m.getAddressesWithState(snap, set, predicate));
	}

	@Override
	public AddressSetView getAddressesWithState(long snap, Predicate<TraceMemoryState> predicate) {
		return new UnionAddressSetView(getActiveSpaces().stream()
				.map(m -> m.getAddressesWithState(snap, predicate))
				.toList());
	}

	@Override
	public AddressSetView getAddressesWithState(Lifespan lifespan,
			Predicate<TraceMemoryState> predicate) {
		return new UnionAddressSetView(getActiveSpaces().stream()
				.map(m -> m.getAddressesWithState(lifespan, predicate))
				.toList());
	}

	protected Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> doGetStates(Lifespan span,
			AddressRange range) {
		return delegateReadOr(range.getAddressSpace(), m -> m.doGetStates(span, range),
			() -> List.of(Map.entry(new ImmutableTraceAddressSnapRange(range, span),
				TraceMemoryState.UNKNOWN)));
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
		MemBuffer buffer =
			delegateRead(start.getAddressSpace(), m -> m.getBufferAt(snap, start, byteOrder));
		if (buffer == null) {
			return new DBTraceEmptyMemBuffer(trace, start, byteOrder);
		}
		return buffer;
	}

	@Override
	public Long getSnapOfMostRecentChangeToBlock(long snap, Address address) {
		return delegateRead(address.getAddressSpace(),
			m -> m.getSnapOfMostRecentChangeToBlock(snap, address));
	}

	@Override
	public int getBlockSize() {
		return DBTraceMemorySpace.BLOCK_SIZE;
	}

	@Override
	public void pack() {
		delegateWriteAll(getActiveSpaces(), m -> m.pack());
	}

	@Override
	public Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> getStateChanges(long from,
			long to) {
		if (from == to) {
			return Collections.emptySet();
		}
		Lifespan between = from < to ? Lifespan.span(from + 1, to) : Lifespan.span(to + 1, from);
		Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> result = new ArrayList<>();
		for (DBTraceMemorySpace space : spaces.values()) {
			AddressRange rng =
				new AddressRangeImpl(space.space.getMinAddress(), space.space.getMaxAddress());
			result.addAll(
				space.stateMapSpace.reduce(TraceAddressSnapRangeQuery.enclosed(rng, between))
						.entries());
		}
		return result;
	}
}
