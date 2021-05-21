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

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalNotification;
import com.google.common.collect.Range;

import db.DBHandle;
import ghidra.lifecycle.Unfinished;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.DBTraceUtils.OffsetSnap;
import ghidra.trace.database.listing.DBTraceCodeSpace;
import ghidra.trace.database.map.*;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager.DBTraceSpaceEntry;
import ghidra.trace.database.space.DBTraceSpaceBased;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.*;
import ghidra.trace.model.memory.*;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.trace.util.TraceViewportSpanIterator;
import ghidra.util.*;
import ghidra.util.AddressIteratorAdapter;
import ghidra.util.database.*;
import ghidra.util.database.spatial.rect.Rectangle2DDirection;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Implements {@link TraceMemorySpace} using a database-backed copy-on-write store.
 */
public class DBTraceMemorySpace implements Unfinished, TraceMemorySpace, DBTraceSpaceBased {
	public static final int BLOCK_SHIFT = 12;
	public static final int BLOCK_SIZE = 1 << BLOCK_SHIFT;
	public static final int BLOCK_MASK = -1 << BLOCK_SHIFT;
	public static final int DEPENDENT_COMPRESSED_SIZE_TOLERANCE = BLOCK_SIZE >>> 2;

	public static final int BLOCKS_PER_BUFFER = 256; // Must be a power of 2 and >= 8;

	protected final DBTraceMemoryManager manager;
	protected final DBHandle dbh;
	protected final AddressSpace space;
	protected final ReadWriteLock lock;
	protected final DBTrace trace;

	protected final DBTraceAddressSnapRangePropertyMapSpace<DBTraceMemoryRegion, DBTraceMemoryRegion> regionMapSpace;
	protected final DBCachedObjectIndex<String, DBTraceMemoryRegion> regionsByPath;
	protected final Collection<TraceMemoryRegion> regionView;
	protected final Map<DBTraceMemoryRegion, DBTraceMemoryRegion> regionCache = CacheBuilder
			.newBuilder()
			.removalListener(this::regionCacheEntryRemoved)
			.maximumSize(10)
			.build()
			.asMap();

	protected final DBTraceAddressSnapRangePropertyMapSpace<TraceMemoryState, DBTraceMemoryStateEntry> stateMapSpace;

	protected final DBCachedObjectStore<DBTraceMemoryBufferEntry> bufferStore;
	protected final DBCachedObjectStore<DBTraceMemoryBlockEntry> blockStore;
	protected final DBCachedObjectIndex<OffsetSnap, DBTraceMemoryBlockEntry> blocksByOffset;
	protected final Map<OffsetSnap, DBTraceMemoryBlockEntry> blockCache = CacheBuilder
			.newBuilder()
			.removalListener(this::blockCacheEntryRemoved)
			.maximumSize(10)
			.build()
			.asMap();

	public DBTraceMemorySpace(DBTraceMemoryManager manager, DBHandle dbh, AddressSpace space,
			DBTraceSpaceEntry ent) throws IOException, VersionException {
		this.manager = manager;
		this.dbh = dbh;
		this.space = space;
		this.lock = manager.getLock();
		this.trace = manager.getTrace();

		DBCachedObjectStoreFactory factory = trace.getStoreFactory();

		long threadKey = ent.getThreadKey();
		int frameLevel = ent.getFrameLevel();
		this.regionMapSpace = new DBTraceAddressSnapRangePropertyMapSpace<>(
			DBTraceMemoryRegion.tableName(space, threadKey), factory, lock, space,
			DBTraceMemoryRegion.class, (t, s, r) -> new DBTraceMemoryRegion(this, t, s, r));
		this.regionView = Collections.unmodifiableCollection(regionMapSpace.values());
		this.regionsByPath =
			regionMapSpace.getUserIndex(String.class, DBTraceMemoryRegion.PATH_COLUMN);

		this.stateMapSpace = new DBTraceAddressSnapRangePropertyMapSpace<>(
			DBTraceMemoryStateEntry.tableName(space, threadKey, frameLevel), factory, lock, space,
			DBTraceMemoryStateEntry.class, DBTraceMemoryStateEntry::new);

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
	}

	private void regionCacheEntryRemoved(
			RemovalNotification<DBTraceMemoryRegion, DBTraceMemoryRegion> rn) {
		// Nothing
	}

	private void blockCacheEntryRemoved(
			RemovalNotification<OffsetSnap, DBTraceMemoryBlockEntry> rn) {
		// Nothing
	}

	@Override
	public Trace getTrace() {
		return trace;
	}

	@Override
	public DBTraceMemoryRegion addRegion(String path, Range<Long> lifespan,
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
			trace.updateViewsAddBlock(region);
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
	public Collection<? extends DBTraceMemoryRegion> getRegionsIntersecting(Range<Long> lifespan,
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
			trace.updateViewsDeleteBlock(region);
			trace.setChanged(
				new TraceChangeRecord<>(TraceMemoryRegionChangeType.DELETED, this, region));
		}
	}

	@Override
	public DBTraceCodeSpace getCodeSpace(boolean createIfAbsent) {
		return trace.getCodeManager().getCodeSpace(space, createIfAbsent);
	}

	@Override
	public AddressSpace getAddressSpace() {
		return space;
	}

	@Override
	public DBTraceThread getThread() {
		return null;
	}

	@Override
	public int getFrameLevel() {
		return 0;
	}

	protected void doSetState(long snap, Address start, Address end, TraceMemoryState state) {
		if (state == null) {
			throw new NullPointerException();
		}
		// Go one out to find abutting ranges, too.
		Address prev = start.previous();
		if (prev == null) {
			prev = start;
		}
		Address next = end.next();
		if (next == null) {
			next = end;
		}
		Map<TraceAddressSnapRange, TraceMemoryState> toPut = new HashMap<>();
		for (Entry<TraceAddressSnapRange, TraceMemoryState> entry : stateMapSpace.reduce(
			TraceAddressSnapRangeQuery.intersecting(prev, next, snap, snap)).entries()) {
			// NOTE: Entries are in no particular order
			AddressRange range = entry.getKey().getRange();
			boolean precedesMin = range.getMinAddress().compareTo(start) < 0;
			boolean procedesMax = range.getMaxAddress().compareTo(end) > 0;
			boolean sameState = entry.getValue() == state;
			if (precedesMin && procedesMax && sameState) {
				return; // The value in this range is already the desired state
			}
			stateMapSpace.remove(entry);
			if (precedesMin) {
				if (sameState) {
					start = range.getMinAddress();
				}
				else {
					toPut.put(
						new ImmutableTraceAddressSnapRange(range.getMinAddress(), prev, snap, snap),
						entry.getValue());
				}
			}
			if (procedesMax) {
				if (sameState) {
					end = range.getMaxAddress();
				}
				else {
					toPut.put(
						new ImmutableTraceAddressSnapRange(next, range.getMaxAddress(), snap, snap),
						entry.getValue());
				}
			}
		}
		if (state != TraceMemoryState.UNKNOWN) {
			stateMapSpace.put(start, end, snap, state);
		}
		assert toPut.size() <= 2;
		for (Entry<TraceAddressSnapRange, TraceMemoryState> ent : toPut.entrySet()) {
			stateMapSpace.put(ent.getKey(), ent.getValue());
		}
		trace.setChanged(new TraceChangeRecord<>(TraceMemoryStateChangeType.CHANGED, this,
			new ImmutableTraceAddressSnapRange(start, end, snap, snap), state));
	}

	protected void checkState(TraceMemoryState state) {
		if (state == null || state == TraceMemoryState.UNKNOWN) {
			throw new IllegalArgumentException("Cannot erase memory state without removing bytes");
		}
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
		TraceViewportSpanIterator spit = new TraceViewportSpanIterator(trace, snap);
		while (spit.hasNext()) {
			Range<Long> span = spit.next();
			TraceMemoryState state = getState(span.upperEndpoint(), address);
			switch (state) {
				case KNOWN:
				case ERROR:
					return Map.entry(span.upperEndpoint(), state);
				default: // fall through
			}
			// Only the snap with the schedule specified gets the source snap's states
			if (span.upperEndpoint() - span.lowerEndpoint() > 0) {
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
		TraceViewportSpanIterator spit = new TraceViewportSpanIterator(trace, snap);
		while (spit.hasNext()) {
			Range<Long> span = spit.next();
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
	public AddressSetView getAddressesWithState(Range<Long> lifespan,
			Predicate<TraceMemoryState> predicate) {
		return new DBTraceAddressSnapRangePropertyMapAddressSetView<>(space, lock,
			stateMapSpace.reduce(TraceAddressSnapRangeQuery.intersecting(lifespan, space)),
			predicate);
	}

	@Override
	public AddressSetView getAddressesWithState(long snap, AddressSetView set,
			Predicate<TraceMemoryState> predicate) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			AddressSet remains = new AddressSet(set);
			AddressSet result = new AddressSet();
			while (!remains.isEmpty()) {
				AddressRange range = remains.getFirstRange();
				remains.delete(range);
				for (Entry<TraceAddressSnapRange, TraceMemoryState> entry : stateMapSpace.reduce(
					TraceAddressSnapRangeQuery.intersecting(range.getMinAddress(),
						range.getMaxAddress(), snap, snap)).entries()) {
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

	@Override
	public Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> getStates(long snap,
			AddressRange range) {
		return stateMapSpace.reduce(TraceAddressSnapRangeQuery.intersecting(range.getMinAddress(),
			range.getMaxAddress(), snap, snap)).entries();
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
		ent = blockCache.get(loc);
		if (ent != null) {
			return ent;
		}
		it = blocksByOffset.head(loc, true).descending().values().iterator();
		if (!it.hasNext()) {
			return null;
		}
		ent = it.next();
		if (ent.getOffset() != loc.offset) {
			return null;
		}
		blockCache.put(loc, ent);
		return ent;
	}

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
		if (next.getOffset() != loc.offset) {
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
			blockCache.put(loc, ent);
			return;
		}
		// (1) or (2a)
		ent = blockStore.create();
		ent.setLoc(loc);
		if (ent.cmpBytes(buf, dstOffset, maxLen) == 0) {
			// Keep the entry, but don't allocate storage in a buffer
			buf.position(buf.position() + maxLen);
			return;
		}
		ent.setBytes(buf, dstOffset, maxLen);
		blockCache.put(loc, ent);
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
		Iterator<DBTraceMemoryBlockEntry> it =
			blocksByOffset.tail(new OffsetSnap(loc.offset, loc.snap + 1), true).values().iterator(); // exclusive
		AddressSet remaining = new AddressSet(space.getAddress(loc.offset + dstOffset),
			space.getAddress(loc.offset + dstOffset + maxLen - 1));
		while (it.hasNext()) {
			DBTraceMemoryBlockEntry next = it.next();
			if (next.getOffset() != loc.offset) {
				break;
			}
			AddressSetView withState =
				getAddressesWithState(next.getSnap(), remaining, state -> true);
			remaining = remaining.subtract(withState);
			long endSnap = next.getSnap() - 1;
			for (AddressRange rng : withState) {
				changed.add(
					new ImmutableTraceAddressSnapRange(rng, Range.closed(loc.snap, endSnap)));
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
				changed.add(new ImmutableTraceAddressSnapRange(rng, Range.atLeast(loc.snap)));
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
				trace.setChanged(new TraceChangeRecord<>(TraceMemoryBytesChangeType.CHANGED,
					this, new ImmutableTraceAddressSnapRange(start, start.add(result - 1),
						snap, lastSnap.snap),
					oldBytes.array(), bytes));

				// Fixup affected code units
				DBTraceCodeSpace codeSpace = trace.getCodeManager().get(this, false);
				if (codeSpace != null) {
					codeSpace.bytesChanged(changed, snap, start, oldBytes.array(), bytes);
				}
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
		TraceViewportSpanIterator spit = new TraceViewportSpanIterator(trace, snap);
		spans: while (spit.hasNext()) {
			Range<Long> span = spit.next();
			Iterator<AddressRange> arit =
				getAddressesWithState(span, s -> s == TraceMemoryState.KNOWN).iterator(start, true);
			while (arit.hasNext()) {
				AddressRange rng = arit.next();
				if (rng.getMinAddress().compareTo(toRead.getMaxAddress()) > 0) {
					break;
				}
				for (AddressRange sub : remains.intersectRange(rng.getMinAddress(),
					rng.getMaxAddress())) {
					sources.put(sub, span.upperEndpoint());
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
			buf.position(pos + offset);
			int read = getBytes(ent.getValue(), rng.getMinAddress(), buf);
			if (read < length) {
				break;
			}
		}
		// We "got it all", even if there were gaps in "KNOWN"
		buf.limit(lim);
		buf.position(pos + len);
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
			stateMapSpace.getAddressSetView(Range.all(), s -> s == TraceMemoryState.KNOWN))
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

	// TODO: Test this
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

	public long getFirstChange(Range<Long> span, AddressRange range) {
		assertInSpace(range);
		long lower = DBTraceUtils.lowerEndpoint(span);
		long upper = DBTraceUtils.upperEndpoint(span);
		if (lower == upper) {
			return Long.MIN_VALUE;
		}
		Range<Long> fwdOne = DBTraceUtils.toRange(lower + 1, upper);
		ByteBuffer buf1 = ByteBuffer.allocate(BLOCK_SIZE);
		ByteBuffer buf2 = ByteBuffer.allocate(BLOCK_SIZE);
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			for (TraceAddressSnapRange tasr : stateMapSpace.reduce(
				TraceAddressSnapRangeQuery.intersecting(range, fwdOne)
						.starting(
							Rectangle2DDirection.BOTTOMMOST))
					.orderedKeys()) {
				AddressRange toExamine = range.intersect(tasr.getRange());
				if (doCheckBytesChanged(tasr.getY1(), toExamine, buf1, buf2)) {
					return tasr.getY1();
				}
			}
			return Long.MIN_VALUE;
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
			if (snap != 0) {
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
			stateMapSpace.invalidateCache();
			bufferStore.invalidateCache();
			blockStore.invalidateCache();
			blockCache.clear();
		}
	}
}
