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
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.Predicate;

import db.DBHandle;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceTimeViewport;
import ghidra.trace.database.DBTraceUtils.AddressRangeMapSetter;
import ghidra.trace.database.DBTraceUtils.OffsetSnap;
import ghidra.trace.database.listing.DBTraceCodeSpace;
import ghidra.trace.database.map.*;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager.DBTraceSpaceEntry;
import ghidra.trace.database.space.DBTraceSpaceBased;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.*;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.*;
import ghidra.util.AddressIteratorAdapter;
import ghidra.util.database.*;
import ghidra.util.database.spatial.rect.Rectangle2DDirection;
import ghidra.util.datastruct.FixedSizeHashMap;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Implements {@link TraceMemorySpace} using a database-backed copy-on-write store.
 */
public class DBTraceMemorySpace
		implements TraceMemorySpace, InternalTraceMemoryOperations, DBTraceSpaceBased {
	public static final int BLOCK_SHIFT = 12;
	public static final int BLOCK_SIZE = 1 << BLOCK_SHIFT;
	public static final int BLOCK_MASK = -1 << BLOCK_SHIFT;
	public static final int DEPENDENT_COMPRESSED_SIZE_TOLERANCE = BLOCK_SIZE >>> 2;

	public static final int BLOCKS_PER_BUFFER = 256; // Must be a power of 2 and >= 8;

	protected final DBTraceMemoryManager manager;
	protected final DBHandle dbh;
	protected final AddressSpace space;
	protected final TraceThread thread;
	protected final int frameLevel;
	protected final ReadWriteLock lock;
	protected final DBTrace trace;

	protected final DBTraceAddressSnapRangePropertyMapSpace<DBTraceMemoryRegion, DBTraceMemoryRegion> regionMapSpace;
	protected final DBCachedObjectIndex<String, DBTraceMemoryRegion> regionsByPath;
	protected final Collection<TraceMemoryRegion> regionView;
	protected final Map<DBTraceMemoryRegion, DBTraceMemoryRegion> regionCache =
		new FixedSizeHashMap<>(10);

	protected final DBTraceAddressSnapRangePropertyMapSpace<TraceMemoryState, DBTraceMemoryStateEntry> stateMapSpace;

	protected final DBCachedObjectStore<DBTraceMemoryBufferEntry> bufferStore;
	protected final DBCachedObjectStore<DBTraceMemoryBlockEntry> blockStore;
	protected final DBCachedObjectIndex<OffsetSnap, DBTraceMemoryBlockEntry> blocksByOffset;
	protected final Map<OffsetSnap, DBTraceMemoryBlockEntry> blockCacheMostRecent =
		new FixedSizeHashMap<>(10);

	protected final DBTraceTimeViewport viewport;

	public DBTraceMemorySpace(DBTraceMemoryManager manager, DBHandle dbh, AddressSpace space,
			DBTraceSpaceEntry ent, TraceThread thread) throws IOException, VersionException {
		this.manager = manager;
		this.dbh = dbh;
		this.space = space;
		this.thread = thread;
		this.frameLevel = ent.getFrameLevel();
		this.lock = manager.getLock();
		this.trace = manager.getTrace();

		DBCachedObjectStoreFactory factory = trace.getStoreFactory();

		long threadKey = ent.getThreadKey();
		int frameLevel = ent.getFrameLevel();
		this.regionMapSpace = new DBTraceAddressSnapRangePropertyMapSpace<>(
			DBTraceMemoryRegion.tableName(space, threadKey), factory, lock, space, thread,
			frameLevel, DBTraceMemoryRegion.class,
			(t, s, r) -> new DBTraceMemoryRegion(this, t, s, r));
		this.regionView = Collections.unmodifiableCollection(regionMapSpace.values());
		this.regionsByPath =
			regionMapSpace.getUserIndex(String.class, DBTraceMemoryRegion.PATH_COLUMN);

		this.stateMapSpace = new DBTraceAddressSnapRangePropertyMapSpace<>(
			DBTraceMemoryStateEntry.tableName(space, threadKey, frameLevel), factory, lock, space,
			thread, frameLevel, DBTraceMemoryStateEntry.class, DBTraceMemoryStateEntry::new);

		this.bufferStore = factory.getOrCreateCachedStore(
			DBTraceMemoryBufferEntry.tableName(space, threadKey, frameLevel),
			DBTraceMemoryBufferEntry.class, (s, r) -> new DBTraceMemoryBufferEntry(dbh, s, r),
			true);

		this.blockStore = factory.getOrCreateCachedStore(
			DBTraceMemoryBlockEntry.tableName(space, threadKey, frameLevel),
			DBTraceMemoryBlockEntry.class, (s, r) -> new DBTraceMemoryBlockEntry(this, s, r),
			true);
		this.blocksByOffset =
			blockStore.getIndex(OffsetSnap.class, DBTraceMemoryBlockEntry.LOCATION_COLUMN);

		this.viewport = trace.createTimeViewport();
	}

	@Override
	public AddressSpace getSpace() {
		return space;
	}

	@Override
	public ReadWriteLock getLock() {
		return lock;
	}

	@Override
	public Trace getTrace() {
		return trace;
	}

	@Override
	public DBTraceMemoryRegion addRegion(String path, Lifespan lifespan,
			AddressRange range, Collection<TraceMemoryFlag> flags)
			throws TraceOverlappedRegionException, DuplicateNameException {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			Collection<? extends DBTraceMemoryRegion> conflicts =
				getRegionsIntersecting(lifespan, range);
			if (!conflicts.isEmpty()) {
				throw new TraceOverlappedRegionException(conflicts);
			}
			if (!manager.getRegionsWithPathInLifespan(lifespan, path).isEmpty()) {
				throw new DuplicateNameException(
					"A region having path '" + path +
						"' already exists within an overlapping snap");
			}
			DBTraceMemoryRegion region =
				regionMapSpace.put(new ImmutableTraceAddressSnapRange(range, lifespan), null);
			region.set(path, path, flags);
			trace.updateViewsAddRegionBlock(region);
			trace.setChanged(
				new TraceChangeRecord<>(TraceMemoryRegionChangeType.ADDED, this, region));
			return region;
		}
	}

	@Override
	public Collection<TraceMemoryRegion> getAllRegions() {
		return regionView;
	}

	@Override
	public DBTraceMemoryRegion getLiveRegionByPath(long snap, String path) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			for (DBTraceMemoryRegion region : regionCache.keySet()) {
				if (!region.getLifespan().contains(snap)) {
					continue;
				}
				if (!path.equals(region.getPath())) {
					continue;
				}
				return region;
			}
			for (DBTraceMemoryRegion region : regionsByPath.get(path)) {
				if (!region.getLifespan().contains(snap)) {
					continue;
				}
				regionCache.put(region, region);
				return region;
			}
			return null;
		}
	}

	@Override
	public DBTraceMemoryRegion getRegionContaining(long snap, Address address) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			for (DBTraceMemoryRegion region : regionCache.keySet()) {
				if (!region.getShape().contains(address, snap)) {
					continue;
				}
				return region;
			}
			DBTraceMemoryRegion region =
				regionMapSpace.reduce(TraceAddressSnapRangeQuery.at(address, snap)).firstValue();
			if (region != null) {
				regionCache.put(region, region);
			}
			return region;
		}
	}

	@Override
	public Collection<? extends DBTraceMemoryRegion> getRegionsIntersecting(Lifespan lifespan,
			AddressRange range) {
		return Collections.unmodifiableCollection(regionMapSpace.reduce(
			TraceAddressSnapRangeQuery.intersecting(range, lifespan)).values());
	}

	@Override
	public Collection<? extends DBTraceMemoryRegion> getRegionsAtSnap(long snap) {
		return Collections.unmodifiableCollection(
			regionMapSpace.reduce(TraceAddressSnapRangeQuery.atSnap(snap, space)).values());
	}

	@Override
	public AddressSetView getRegionsAddressSet(long snap) {
		return getRegionsAddressSetWith(snap, r -> true);
	}

	@Override
	public AddressSetView getRegionsAddressSetWith(long snap,
			Predicate<TraceMemoryRegion> predicate) {
		return new DBTraceAddressSnapRangePropertyMapAddressSetView<>(space, lock,
			regionMapSpace.reduce(TraceAddressSnapRangeQuery.atSnap(snap, space)),
			predicate);
	}

	void deleteRegion(DBTraceMemoryRegion region) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			regionMapSpace.deleteData(region);
			regionCache.remove(region);
			trace.updateViewsDeleteRegionBlock(region);
			trace.setChanged(
				new TraceChangeRecord<>(TraceMemoryRegionChangeType.DELETED, this, region));
		}
	}

	@Override
	public DBTraceCodeSpace getCodeSpace(boolean createIfAbsent) {
		if (space.isRegisterSpace() && !space.isOverlaySpace()) {
			return trace.getCodeManager().getCodeRegisterSpace(thread, frameLevel, createIfAbsent);
		}
		return trace.getCodeManager().getCodeSpace(space, createIfAbsent);
	}

	@Override
	public AddressSpace getAddressSpace() {
		return space;
	}

	@Override
	public TraceThread getThread() {
		return thread;
	}

	@Override
	public int getFrameLevel() {
		return frameLevel;
	}

	protected void doSetState(long snap, Address start, Address end, TraceMemoryState state) {
		if (state == null) {
			throw new NullPointerException();
		}
		var l = new Object() {
			boolean changed;
		};
		new AddressRangeMapSetter<Entry<TraceAddressSnapRange, TraceMemoryState>, TraceMemoryState>() {
			@Override
			protected AddressRange getRange(Entry<TraceAddressSnapRange, TraceMemoryState> entry) {
				return entry.getKey().getRange();
			}

			@Override
			protected TraceMemoryState getValue(
					Entry<TraceAddressSnapRange, TraceMemoryState> entry) {
				return entry.getValue();
			}

			@Override
			protected void remove(Entry<TraceAddressSnapRange, TraceMemoryState> entry) {
				stateMapSpace.remove(entry);
			}

			@Override
			protected Iterable<Entry<TraceAddressSnapRange, TraceMemoryState>> getIntersecting(
					Address lower, Address upper) {
				return stateMapSpace
						.reduce(TraceAddressSnapRangeQuery.intersecting(lower, upper, snap, snap))
						.entries();
			}

			@Override
			protected Entry<TraceAddressSnapRange, TraceMemoryState> put(AddressRange range,
					TraceMemoryState value) {
				// This should not get called if the range is already the desired state
				l.changed = true;
				if (value != TraceMemoryState.UNKNOWN) {
					stateMapSpace.put(new ImmutableTraceAddressSnapRange(range, snap), value);
				}
				return null; // Don't need to return it
			}
		}.set(start, end, state);

		if (l.changed) {
			trace.setChanged(new TraceChangeRecord<>(TraceMemoryStateChangeType.CHANGED, this,
				new ImmutableTraceAddressSnapRange(start, end, snap, snap), state));
		}
	}

	protected void checkState(TraceMemoryState state) {
		/**
		 * TODO: I don't remember why I prohibited this originally. It seems some technicality in
		 * calling something "last known?" We might revisit and specify that definition, in the face
		 * of memory being invalidated while the target is suspended. It seems appropriate to leave
		 * the stale bytes in the trace, but change the state to UNKNOWN. Do those stale bytes still
		 * count as last known? Aside from getBytes, I don't see anything that requires a precise
		 * distinction. We might be careful how this interacts with removeBytes, though.... Well,
		 * AFAICT, it doesn't depend on state markings. For now, I'm going to allow it. We'll see
		 * what happens. Changing this had no effect on the unit tests :/ .
		 */
		/*if (state == null || state == TraceMemoryState.UNKNOWN) {
			throw new IllegalArgumentException("Cannot erase memory state without removing bytes");
		}*/
	}

	@Override
	// TODO: Ensure a code unit is not having rug taken out from under it?
	public void setState(long snap, Address start, Address end, TraceMemoryState state) {
		checkState(state);
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			doSetState(snap, start, end, state);
		}
	}

	@Override
	public void setState(long snap, AddressRange range, TraceMemoryState state) {
		checkState(state);
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			doSetState(snap, range.getMinAddress(), range.getMaxAddress(), state);
		}
	}

	@Override
	public void setState(long snap, Address address, TraceMemoryState state) {
		checkState(state);
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			doSetState(snap, address, address, state);
		}
	}

	@Override
	public void setState(long snap, AddressSetView set, TraceMemoryState state) {
		checkState(state);
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			for (AddressRange range : set) {
				doSetState(snap, range.getMinAddress(), range.getMaxAddress(), state);
			}
		}
	}

	@Override
	public TraceMemoryState getState(long snap, Address address) {
		TraceMemoryState state =
			stateMapSpace.reduce(TraceAddressSnapRangeQuery.at(address, snap)).firstValue();
		return state == null ? TraceMemoryState.UNKNOWN : state;
	}

	@Override
	public Entry<Long, TraceMemoryState> getViewState(long snap, Address address) {
		for (Lifespan span : viewport.getOrderedSpans(snap)) {
			TraceMemoryState state = getState(span.lmax(), address);
			switch (state) {
				case KNOWN:
				case ERROR:
					return Map.entry(span.lmax(), state);
				default: // fall through
			}
			// Only the snap with the schedule specified gets the source snap's states
			if (span.lmax() - span.lmin() > 0) {
				return Map.entry(snap, TraceMemoryState.UNKNOWN);
			}
		}
		return Map.entry(snap, TraceMemoryState.UNKNOWN);
	}

	@Override
	public Entry<TraceAddressSnapRange, TraceMemoryState> getMostRecentStateEntry(long snap,
			Address address) {
		return stateMapSpace.reduce(
			TraceAddressSnapRangeQuery.mostRecent(address, snap)).firstEntry();
	}

	@Override
	public Entry<TraceAddressSnapRange, TraceMemoryState> getViewMostRecentStateEntry(long snap,
			Address address) {
		for (Lifespan span : viewport.getOrderedSpans(snap)) {
			Entry<TraceAddressSnapRange, TraceMemoryState> entry =
				stateMapSpace.reduce(TraceAddressSnapRangeQuery.mostRecent(address, span))
						.firstEntry();
			if (entry != null) {
				return entry;
			}
		}
		return null;
	}

	@Override
	public AddressSetView getAddressesWithState(long snap, Predicate<TraceMemoryState> predicate) {
		return new DBTraceAddressSnapRangePropertyMapAddressSetView<>(space, lock,
			stateMapSpace.reduce(TraceAddressSnapRangeQuery.atSnap(snap, space)),
			predicate);
	}

	@Override
	public AddressSetView getAddressesWithState(Lifespan lifespan,
			Predicate<TraceMemoryState> predicate) {
		return new DBTraceAddressSnapRangePropertyMapAddressSetView<>(space, lock,
			stateMapSpace.reduce(TraceAddressSnapRangeQuery.intersecting(lifespan, space)),
			predicate);
	}

	@Override
	public AddressSetView getAddressesWithState(Lifespan span, AddressSetView set,
			Predicate<TraceMemoryState> predicate) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			AddressSet remains = new AddressSet(set);
			AddressSet result = new AddressSet();
			while (!remains.isEmpty()) {
				AddressRange range = remains.getFirstRange();
				remains.delete(range);
				for (Entry<TraceAddressSnapRange, TraceMemoryState> entry : doGetStates(span,
					range)) {
					AddressRange foundRange = entry.getKey().getRange();
					remains.delete(foundRange);
					if (predicate.test(entry.getValue())) {
						result.add(foundRange);
					}
				}
			}
			return result;
		}
	}

	protected Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> doGetStates(Lifespan span,
			AddressRange range) {
		// TODO: A better way to handle memory-mapped registers?
		if (getAddressSpace().isRegisterSpace() && !range.getAddressSpace().isRegisterSpace()) {
			return trace.getMemoryManager().doGetStates(span, range);
		}
		return stateMapSpace.reduce(TraceAddressSnapRangeQuery.intersecting(range, span)).entries();
	}

	@Override
	public Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> getStates(long snap,
			AddressRange range) {
		assertInSpace(range);
		return doGetStates(Lifespan.at(snap), range);
	}

	@Override
	public Iterable<Entry<TraceAddressSnapRange, TraceMemoryState>> getMostRecentStates(
			TraceAddressSnapRange within) {
		return new DBTraceAddressSnapRangePropertyMapOcclusionIntoPastIterable<>(this.stateMapSpace,
			within);
	}

	protected DBTraceMemoryBlockEntry findMostRecentBlockEntry(OffsetSnap loc, boolean inclusive) {
		DBTraceMemoryBlockEntry ent = null;
		Iterator<DBTraceMemoryBlockEntry> it;
		if (!inclusive) {
			loc = new OffsetSnap(loc.offset, loc.snap - 1);
		}
		ent = blockCacheMostRecent.get(loc);
		if (ent != null) {
			return ent;
		}
		it = blocksByOffset.head(loc, true).descending().values().iterator();
		if (!it.hasNext()) {
			return null;
		}
		ent = it.next();
		if (ent.getOffset() != loc.offset || ent.isScratch() != loc.isScratch()) {
			return null;
		}
		blockCacheMostRecent.put(loc, ent);
		return ent;
	}

	/**
	 * Locate the soonest block entry for the given offset-snap pair
	 * 
	 * <p>
	 * To qualify, the entry must have a snap greater than (or optionally equal to) that given and
	 * an offset exactly equal to that given. That is, it is the earliest in time, but most follow
	 * the given snap. Additionally, if the given snap is in scratch space, the found entry must
	 * also be in scratch space.
	 * 
	 * @param loc the offset-snap pair
	 * @param inclusive true to allow equal snap
	 * @return the found entry, or null
	 */
	protected DBTraceMemoryBlockEntry findSoonestBlockEntry(OffsetSnap loc, boolean inclusive) {
		Iterator<DBTraceMemoryBlockEntry> it;
		if (inclusive) {
			it = blocksByOffset.tail(loc, true).values().iterator();
		}
		else {
			it = blocksByOffset.tail(new OffsetSnap(loc.offset, loc.snap + 1),
				true).values().iterator();
		}
		if (!it.hasNext()) {
			return null;
		}
		DBTraceMemoryBlockEntry next = it.next();
		if (next.getOffset() != loc.offset || next.isScratch() != loc.isScratch()) {
			return null;
		}
		return next;
	}

	protected void doPutBytes(OffsetSnap loc, ByteBuffer buf, int dstOffset, int maxLen)
			throws IOException {
		// Cases:
		// 1) An entry does not exist
		// 2) An entry does exist, but it's not "present"
		// 2a) The update does not cause a change
		// 2b) The update does cause a change
		// 3) An entry exists, and it's present
		DBTraceMemoryBlockEntry ent = findMostRecentBlockEntry(loc, true);
		if (ent != null) { // Deal with (1) later
			if (ent.getSnap() == loc.snap) { // (3) Just update it.
				// No need to compare, because a NOP set won't hurt.
				ent.setBytes(buf, dstOffset, maxLen);
				return;
			}
			// (2)...
			if (ent.cmpBytes(buf, dstOffset, maxLen) == 0) {
				// (2a)
				buf.position(buf.position() + maxLen);
				return;
			}
			ent = ent.copy(loc);
			ent.setBytes(buf, dstOffset, maxLen);
			return;
		}
		// (1) or (2b)
		ent = blockStore.create();
		ent.setLoc(loc);
		blockCacheMostRecent.clear();
		blockCacheMostRecent.put(loc, ent);
		if (ent.cmpBytes(buf, dstOffset, maxLen) == 0) {
			// Keep the entry, but don't allocate storage in a buffer
			buf.position(buf.position() + maxLen);
			return;
		}
		ent.setBytes(buf, dstOffset, maxLen);
	}

	protected static class OutSnap {
		long snap;

		public OutSnap(long snap) {
			this.snap = snap;
		}
	}

	protected void doPutFutureBytes(OffsetSnap loc, ByteBuffer buf, int dstOffset, int maxLen,
			OutSnap lastSnap, Set<TraceAddressSnapRange> changed) throws IOException {
		// NOTE: Do not leave the buffer advanced from here
		int pos = buf.position();
		// exclusive?
		Iterator<DBTraceMemoryBlockEntry> it =
			blocksByOffset.tail(new OffsetSnap(loc.offset, loc.snap + 1), true).values().iterator();
		AddressSet remaining = new AddressSet(space.getAddress(loc.offset + dstOffset),
			space.getAddress(loc.offset + dstOffset + maxLen - 1));
		while (it.hasNext()) {
			DBTraceMemoryBlockEntry next = it.next();
			if (next.getOffset() != loc.offset || next.isScratch() != loc.isScratch()) {
				break;
			}
			AddressSetView withState =
				getAddressesWithState(next.getSnap(), remaining, state -> true);
			remaining = remaining.subtract(withState);
			long endSnap = next.getSnap() - 1;
			for (AddressRange rng : withState) {
				changed.add(
					new ImmutableTraceAddressSnapRange(rng, Lifespan.span(loc.snap, endSnap)));
			}
			if (remaining.isEmpty()) {
				lastSnap.snap = endSnap;
				break;
			}
			for (AddressRange rng : remaining) {
				int subOffset = (int) (rng.getMinAddress().getOffset() - loc.offset);
				buf.position(pos + subOffset - dstOffset);
				next.setBytes(buf, subOffset, (int) rng.getLength());
			}
		}
		if (!remaining.isEmpty()) {
			lastSnap.snap = Long.MAX_VALUE;
			for (AddressRange rng : remaining) {
				changed.add(
					new ImmutableTraceAddressSnapRange(rng, Lifespan.nowOnMaybeScratch(loc.snap)));
			}
		}
		buf.position(pos);
	}

	protected int doPutBytes(long snap, Address start, ByteBuffer buf, OutSnap lastSnap,
			Set<TraceAddressSnapRange> changed) throws IOException {
		int result = 0;
		try {
			int maxLen;
			for (Address cur = start; buf.hasRemaining(); cur = cur.addNoWrap(maxLen)) {
				long offset = cur.getOffset();
				long roundOffset = offset & BLOCK_MASK;
				int dstOffset = (int) (offset - roundOffset);
				maxLen = Math.min(BLOCK_SIZE - dstOffset, buf.remaining());
				OffsetSnap loc = new OffsetSnap(roundOffset, snap);
				doPutFutureBytes(loc, buf, dstOffset, maxLen, lastSnap, changed);
				doPutBytes(loc, buf, dstOffset, maxLen);
				result += maxLen;
			}
		}
		catch (AddressOverflowException e) {
			// exited loop
		}
		return result;
	}

	@Override
	public int putBytes(long snap, Address start, ByteBuffer buf) {
		assertInSpace(start);
		int arrOff = buf.arrayOffset() + buf.position();
		try (LockHold hold = LockHold.lock(lock.writeLock())) {

			ByteBuffer oldBytes = ByteBuffer.allocate(buf.remaining());
			getBytes(snap, start, oldBytes);

			OutSnap lastSnap = new OutSnap(snap);
			Set<TraceAddressSnapRange> changed = new HashSet<>();
			int result = doPutBytes(snap, start, buf, lastSnap, changed);
			if (result > 0) {
				Address end = start.add(result - 1);
				doSetState(snap, start, end, TraceMemoryState.KNOWN);

				// Read back the written bytes and fire event
				byte[] bytes = Arrays.copyOfRange(buf.array(), arrOff, arrOff + result);
				ImmutableTraceAddressSnapRange tasr = new ImmutableTraceAddressSnapRange(start,
					start.add(result - 1), snap, lastSnap.snap);
				trace.setChanged(new TraceChangeRecord<>(TraceMemoryBytesChangeType.CHANGED,
					this, tasr, oldBytes.array(), bytes));

				// Fixup affected code units
				DBTraceCodeSpace codeSpace = trace.getCodeManager().get(this, false);
				if (codeSpace != null) {
					codeSpace.bytesChanged(changed, snap, start, oldBytes.array(), bytes);
				}
				// Clear program view caches
				trace.updateViewsBytesChanged(tasr.getRange());
			}
			return result;
		}
		catch (IOException e) {
			blockStore.dbError(e);
			return 0;
		}
	}

	protected void doGetBytes(OffsetSnap loc, ByteBuffer buf, int srcOffset, int maxLen)
			throws IOException {
		DBTraceMemoryBlockEntry ent = findMostRecentBlockEntry(loc, true);
		if (ent == null) {
			// TODO: Write zeroes instead?
			buf.position(buf.position() + maxLen);
		}
		else {
			ent.getBytes(buf, srcOffset, maxLen);
		}
	}

	@Override
	public int getBytes(long snap, Address start, ByteBuffer buf) {
		assertInSpace(start);
		int result = 0;
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			int maxLen;
			for (Address cur = start; buf.hasRemaining(); cur = cur.addNoWrap(maxLen)) {
				long offset = cur.getOffset();
				long roundOffset = offset & BLOCK_MASK;
				int srcOffset = (int) (offset - roundOffset);
				maxLen = Math.min(BLOCK_SIZE - srcOffset, buf.remaining());
				OffsetSnap loc = new OffsetSnap(roundOffset, snap);
				doGetBytes(loc, buf, srcOffset, maxLen);
				result += maxLen;
			}
		}
		catch (AddressOverflowException e) {
			// exited loop
		}
		catch (IOException e) {
			blockStore.dbError(e);
		}
		return result;
	}

	protected int truncateLen(int len, Address start) {
		long maxLen = start.getAddressSpace().getMaxAddress().subtract(start) + 1;
		if (maxLen == 0) {
			// Only happens when min=0 and max=ffff_ffff_ffff_ffff
			return len;
		}
		return MathUtilities.unsignedMin(len, maxLen);
	}

	@Override
	public int getViewBytes(long snap, Address start, ByteBuffer buf) {
		assertInSpace(start);
		AddressRange toRead;
		int len = truncateLen(buf.remaining(), start);
		if (len == 0) {
			return 0;
		}
		try {
			toRead = new AddressRangeImpl(start, len);
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
		Map<AddressRange, Long> sources = new TreeMap<>();
		AddressSet remains = new AddressSet(toRead);

		spans: for (Lifespan span : viewport.getOrderedSpans(snap)) {
			Iterator<AddressRange> arit =
				getAddressesWithState(span, s -> s == TraceMemoryState.KNOWN).iterator(start, true);
			while (arit.hasNext()) {
				AddressRange rng = arit.next();
				if (rng.getMinAddress().compareTo(toRead.getMaxAddress()) > 0) {
					break;
				}
				for (AddressRange sub : remains.intersectRange(rng.getMinAddress(),
					rng.getMaxAddress())) {
					sources.put(sub, span.lmax());
				}
				remains.delete(rng);
				if (remains.isEmpty()) {
					break spans;
				}
			}
		}
		int lim = buf.limit();
		int pos = buf.position();
		for (Map.Entry<AddressRange, Long> ent : sources.entrySet()) {
			AddressRange rng = ent.getKey();
			int offset = (int) rng.getMinAddress().subtract(toRead.getMinAddress());
			int length = (int) rng.getLength();
			buf.limit(pos + offset + length);
			while (buf.position() < pos + offset) {
				buf.put((byte) 0); // fill gaps with 0
			}
			int read = getBytes(ent.getValue(), rng.getMinAddress(), buf);
			if (read < length) {
				break;
			}
		}
		// We "got it all", even if there were gaps in "KNOWN"
		buf.limit(lim);
		while (buf.position() < pos + len) {
			buf.put((byte) 0); // fill final gap with 0
		}
		return len;
	}

	protected Address doFindBytesInRange(long snap, AddressRange range, ByteBuffer data,
			ByteBuffer mask, boolean forward, TaskMonitor monitor) {
		int len = data.capacity();
		assert len != 0; // Caller should have checked
		if (range.getLength() > 0 /*treat length unsigned*/ && range.getLength() < len) {
			return null;
		}

		AddressRange rangeOfStarts =
			new AddressRangeImpl(range.getMinAddress(), range.getMaxAddress().subtract(len - 1));
		ByteBuffer read = ByteBuffer.allocate(len);
		for (Address addr : AddressIteratorAdapter.forRange(rangeOfStarts, forward)) {
			monitor.incrementProgress(1);
			if (monitor.isCancelled()) {
				return null;
			}
			read.clear();
			int l = getBytes(snap, addr, read);
			if (l != len) {
				continue;
			}
			if (!ByteBufferUtils.maskedEquals(mask, data, read)) {
				continue;
			}
			return addr;
		}
		return null;
	}

	@Override
	public Address findBytes(long snap, AddressRange range, ByteBuffer data, ByteBuffer mask,
			boolean forward, TaskMonitor monitor) {
		// ProgramDB uses the naive method with some skipping, so here we go....
		// TODO: This could be made faster by skipping over non-initialized blocks
		// TODO: DFA method would be complicated by masks....
		int len = data.capacity();
		if (mask != null && mask.capacity() != len) {
			throw new IllegalArgumentException("data and mask must have same capacity");
		}
		if (len == 0 ||
			range.getLength() > 0 /*treat length unsigned*/ && range.getLength() < len) {
			return null;
		}

		// TODO: Could do better, but have to worry about viewport, too
		// This will reduce the search to ranges that have been written at any snap
		// We could do for this and previous snaps, but that's where the viewport comes in.
		// TODO: Potentially costly to pre-compute the set concretely
		AddressSet known = new AddressSet(
			stateMapSpace.getAddressSetView(Lifespan.ALL, s -> s == TraceMemoryState.KNOWN))
					.intersect(new AddressSet(range));
		monitor.initialize(known.getNumAddresses());
		for (AddressRange knownRange : known.getAddressRanges(forward)) {
			Address found = doFindBytesInRange(snap, knownRange, data, mask, forward, monitor);
			if (found != null) {
				return found;
			}
		}
		return null;
	}

	protected boolean doCheckBytesChanged(OffsetSnap loc, int srcOffset, int maxLen,
			ByteBuffer eBuf, ByteBuffer pBuf) throws IOException {
		DBTraceMemoryBlockEntry ent = findMostRecentBlockEntry(loc, true);
		if (ent == null || ent.getSnap() < loc.snap) {
			return false;
		}
		DBTraceMemoryBlockEntry pre = findMostRecentBlockEntry(loc, false);
		int eLen = ent.getBytes(eBuf, srcOffset, maxLen);
		assert eLen == maxLen;
		eBuf.flip();
		if (pre == null) {
			return !DBTraceMemoryBlockEntry.isZeroes(eBuf, eLen);
		}
		int pLen = pre.getBytes(pBuf, srcOffset, maxLen);
		pBuf.flip();
		assert eLen == pLen;
		for (int i = 0; i < eLen; i++) {
			if (eBuf.get(i) != pBuf.get(i)) {
				return true;
			}
		}
		return false;
	}

	protected boolean doCheckBytesChanged(long snap, AddressRange range, ByteBuffer buf1,
			ByteBuffer buf2) throws IOException {
		try {
			int maxLen;
			for (Address cur = range.getMinAddress(); cur.compareTo(
				range.getMaxAddress()) <= 0; cur = cur.addNoWrap(maxLen)) {
				long offset = cur.getOffset();
				long roundOffset = offset & BLOCK_MASK;
				int srcOffset = (int) (offset - roundOffset);
				maxLen =
					(int) Math.min(BLOCK_SIZE - srcOffset, range.getMaxAddress().subtract(cur) + 1);
				OffsetSnap loc = new OffsetSnap(roundOffset, snap);
				if (doCheckBytesChanged(loc, srcOffset, maxLen, buf1, buf2)) {
					return true;
				}
			}
		}
		catch (AddressOverflowException e) {
			// exited loop
		}
		return false;
	}

	@Override
	public Long getSnapOfMostRecentChangeToBlock(long snap, Address address) {
		assertInSpace(address);
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			long offset = address.getOffset();
			long roundOffset = offset & BLOCK_MASK;
			OffsetSnap loc = new OffsetSnap(roundOffset, snap);
			DBTraceMemoryBlockEntry ent = findMostRecentBlockEntry(loc, true);
			if (ent == null) {
				return null;
			}
			return ent.getSnap();
		}
	}

	@Override
	public int getBlockSize() {
		return BLOCK_SIZE;
	}

	protected boolean isCross(long lower, long upper) {
		return lower < 0 && upper >= 0;
	}

	/**
	 * Determine the truncation snap if the given span and range include byte changes
	 * 
	 * <p>
	 * Code units do not understand or accommodate changes in time, so the underlying bytes of the
	 * unit must be the same throughout its lifespan. Typically, units are placed with a desired
	 * creation snap, and then its life is extended into the future opportunistically. Thus, when
	 * truncating, we desire to keep the start snap, then search for the soonest byte change within
	 * the desired lifespan. Furthermore, we generally don't permit a unit to exist in both record
	 * and scratch spaces, i.e., it cannot span both the -1 and 0 snaps.
	 * 
	 * @param span the desired lifespan
	 * @param range the address range covered
	 * @return the first snap that should be excluded, or {@link Long#MIN_VALUE} to indicate no
	 *         change.
	 */
	public long getFirstChange(Lifespan span, AddressRange range) {
		assertInSpace(range);
		long lower = span.lmin();
		long upper = span.lmax();
		if (lower == upper) {
			return Long.MIN_VALUE;
		}
		boolean cross = isCross(lower, upper);
		if (cross && lower == -1) {
			return 0; // Avoid reversal of range end points. 
		}
		Lifespan fwdOne = Lifespan.span(lower + 1, cross ? -1 : upper);
		ByteBuffer buf1 = ByteBuffer.allocate(BLOCK_SIZE);
		ByteBuffer buf2 = ByteBuffer.allocate(BLOCK_SIZE);
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			for (TraceAddressSnapRange tasr : stateMapSpace.reduce(
				TraceAddressSnapRangeQuery.intersecting(range, fwdOne)
						.starting(Rectangle2DDirection.BOTTOMMOST))
					.orderedKeys()) {
				AddressRange toExamine = range.intersect(tasr.getRange());
				if (doCheckBytesChanged(tasr.getY1(), toExamine, buf1, buf2)) {
					return tasr.getY1();
				}
			}
			return cross ? 0 : Long.MIN_VALUE;
		}
		catch (IOException e) {
			blockStore.dbError(e);
			return 0;
		}
	}

	@Override
	public void removeBytes(long snap, Address start, int len) {
		assertInSpace(start);
		/*
		 * TODO: This implementation could be more efficient, but I don't think it will be used
		 * often enough to justify optimization.
		 */
		if (len <= 0) {
			return;
		}
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			ByteBuffer oldBytes = ByteBuffer.allocate(len);
			getBytes(snap, start, oldBytes);
			// New in the sense that they're about to replace the old bytes
			ByteBuffer newBytes = ByteBuffer.allocate(len);
			// NB. Don't want to wrap to Long.MAX_VALUE, but also don't want to read from scratch
			if (snap != 0 && snap != Long.MIN_VALUE) {
				getBytes(snap - 1, start, newBytes);
				newBytes.flip();
			}
			OutSnap lastSnap = new OutSnap(snap);
			Set<TraceAddressSnapRange> changed = new HashSet<>();
			doPutBytes(snap, start, newBytes, lastSnap, changed);
			Address end = start.add(len - 1);
			doSetState(snap, start, end, TraceMemoryState.UNKNOWN);

			// Fire event
			trace.setChanged(new TraceChangeRecord<>(TraceMemoryBytesChangeType.CHANGED,
				this, new ImmutableTraceAddressSnapRange(start,
					start.add(newBytes.position() - 1), snap, lastSnap.snap),
				oldBytes.array(), newBytes.array()));

			// Fixup affected code units
			DBTraceCodeSpace codeSpace = trace.getCodeManager().get(this, false);
			if (codeSpace != null) {
				codeSpace.bytesChanged(changed, snap, start, oldBytes.array(), newBytes.array());
			}
		}
		catch (IOException e) {
			blockStore.dbError(e);
		}
	}

	@Override
	public MemBuffer getBufferAt(long snap, Address start, ByteOrder byteOrder) {
		return new DBTraceMemBuffer(this, snap, start, byteOrder);
	}

	@Override
	public void pack() {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			// TODO: Check and rearrange blocks chronologically
			// TODO: Remove identical, adjacent future blocks
			for (DBTraceMemoryBufferEntry bufEnt : bufferStore.asMap().values()) {
				bufEnt.compress();
			}
		}
		catch (IOException e) {
			bufferStore.dbError(e);
		}
	}

	@Override
	public void invalidateCache() {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			regionMapSpace.invalidateCache();
			regionCache.clear();
			trace.updateViewsRefreshBlocks();
			trace.updateViewsBytesChanged(null);
			stateMapSpace.invalidateCache();
			bufferStore.invalidateCache();
			blockStore.invalidateCache();
			blockCacheMostRecent.clear();
		}
	}
}
