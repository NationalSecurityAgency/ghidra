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
import java.util.*;

import db.DBRecord;
import ghidra.program.model.address.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace.TraceMemoryRegionChangeType;
import ghidra.trace.model.memory.*;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.DBObjectColumn;
import ghidra.util.database.annot.*;
import ghidra.util.exception.DuplicateNameException;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceMemoryRegion
		extends AbstractDBTraceAddressSnapRangePropertyMapData<DBTraceMemoryRegion>
		implements TraceMemoryRegion {
	public static final String TABLE_NAME = "MemoryRegions";

	public static final String PATH_COLUMN_NAME = "Path";
	public static final String NAME_COLUMN_NAME = "Name";
	public static final String FLAGS_COLUMN_NAME = "Flags";

	@DBAnnotatedColumn(PATH_COLUMN_NAME)
	static DBObjectColumn PATH_COLUMN;
	@DBAnnotatedColumn(NAME_COLUMN_NAME)
	static DBObjectColumn NAME_COLUMN;
	@DBAnnotatedColumn(FLAGS_COLUMN_NAME)
	static DBObjectColumn FLAGS_COLUMN;

	static String tableName(AddressSpace space, long threadKey) {
		return DBTraceUtils.tableName(TABLE_NAME, space, threadKey, 0);
	}

	@DBAnnotatedField(column = PATH_COLUMN_NAME, indexed = true)
	private String path;
	@DBAnnotatedField(column = NAME_COLUMN_NAME)
	private String name;
	@DBAnnotatedField(column = FLAGS_COLUMN_NAME)
	private byte flagsByte = 0;

	private final DBTraceMemorySpace space;

	private final EnumSet<TraceMemoryFlag> flags = EnumSet.noneOf(TraceMemoryFlag.class);

	public DBTraceMemoryRegion(DBTraceMemorySpace space,
			DBTraceAddressSnapRangePropertyMapTree<DBTraceMemoryRegion, DBTraceMemoryRegion> tree,
			DBCachedObjectStore<?> store, DBRecord record) {
		super(tree, store, record);
		this.space = space;
	}

	@Override
	protected void fresh(boolean created) throws IOException {
		super.fresh(created);
		if (created) {
			return;
		}
		flags.clear();
		TraceMemoryFlag.fromBits(flags, flagsByte);
	}

	@Override
	protected void setRecordValue(DBTraceMemoryRegion value) {
		// Nothing. The value is the record.
	}

	@Override
	protected DBTraceMemoryRegion getRecordValue() {
		return this;
	}

	void set(String path, String name, Collection<TraceMemoryFlag> flags) {
		this.path = path;
		this.name = name;
		this.flagsByte = 0;
		this.flags.clear();
		for (TraceMemoryFlag f : flags) {
			this.flagsByte |= f.getBits();
			this.flags.add(f);
		}
		update(PATH_COLUMN, NAME_COLUMN, FLAGS_COLUMN);
	}

	@SuppressWarnings("hiding")
	protected void checkOverlapConflicts(Lifespan lifespan, AddressRange range)
			throws TraceOverlappedRegionException {
		Collection<? extends DBTraceMemoryRegion> overlapConflicts =
			space.getRegionsIntersecting(lifespan, range);
		for (TraceMemoryRegion c : overlapConflicts) {
			if (c == this) {
				continue;
			}
			throw new TraceOverlappedRegionException(overlapConflicts);
		}
	}

	@SuppressWarnings("hiding")
	protected void checkPathConflicts(Lifespan lifespan, String path)
			throws DuplicateNameException {
		Collection<TraceMemoryRegion> pathConflicts =
			space.manager.getRegionsWithPathInLifespan(lifespan, path);
		for (TraceMemoryRegion c : pathConflicts) {
			if (c == this) {
				continue;
			}
			throw new DuplicateNameException(
				"Only one region with a given path may occupy the same snap");
		}
	}

	@Override
	public DBTrace getTrace() {
		return space.trace;
	}

	@Override
	public String getPath() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return path;
		}
	}

	@Override
	public void setName(String name) {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			this.name = name;
			update(NAME_COLUMN);
			space.trace.updateViewsChangeRegionBlockName(this);
		}
		space.trace.setChanged(
			new TraceChangeRecord<>(TraceMemoryRegionChangeType.CHANGED, space, this));
	}

	@Override
	public String getName() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return name;
		}
	}

	@Override
	public void setLifespan(Lifespan newLifespan)
			throws TraceOverlappedRegionException, DuplicateNameException {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			checkOverlapConflicts(newLifespan, range);
			checkPathConflicts(newLifespan, path);
			Lifespan oldLifespan = getLifespan();
			doSetLifespan(newLifespan);
			space.trace.updateViewsChangeRegionBlockLifespan(this, oldLifespan, newLifespan);
			space.trace.setChanged(
				new TraceChangeRecord<>(TraceMemoryRegionChangeType.LIFESPAN_CHANGED,
					space, this, oldLifespan, newLifespan));
		}
	}

	@Override
	public void setCreationSnap(long creationSnap)
			throws DuplicateNameException, TraceOverlappedRegionException {
		setLifespan(Lifespan.span(creationSnap, getDestructionSnap()));
	}

	@Override
	public long getCreationSnap() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return lifespan.lmin();
		}
	}

	@Override
	public void setDestructionSnap(long destructionSnap)
			throws DuplicateNameException, TraceOverlappedRegionException {
		setLifespan(Lifespan.span(getCreationSnap(), destructionSnap));
	}

	@Override
	public long getDestructionSnap() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return lifespan.lmax();
		}
	}

	@Override
	public void setRange(AddressRange newRange) throws TraceOverlappedRegionException {
		AddressRange oldRange;
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			if (range.equals(newRange)) {
				return;
			}
			oldRange = range;
			checkOverlapConflicts(lifespan, newRange);
			doSetRange(newRange);
			space.trace.updateViewsChangeRegionBlockRange(this, oldRange, newRange);
		}
		space.trace.setChanged(
			new TraceChangeRecord<>(TraceMemoryRegionChangeType.CHANGED, space, this));
	}

	@Override
	public void setMinAddress(Address min) throws TraceOverlappedRegionException {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			setRange(DBTraceUtils.toRange(min, range.getMaxAddress()));
		}
	}

	@Override
	public Address getMinAddress() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return range.getMinAddress();
		}
	}

	@Override
	public void setMaxAddress(Address max) throws TraceOverlappedRegionException {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			setRange(DBTraceUtils.toRange(range.getMinAddress(), max));
		}
	}

	@Override
	public Address getMaxAddress() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return range.getMaxAddress();
		}
	}

	@Override
	public void setLength(long length)
			throws AddressOverflowException, TraceOverlappedRegionException {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			Address minAddress = range.getMinAddress();
			setRange(DBTraceUtils.toRange(minAddress, minAddress.addNoWrap(length - 1)));
		}
	}

	@Override
	public long getLength() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return range.getLength();
		}
	}

	@Override
	public void setFlags(Collection<TraceMemoryFlag> flags) {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			this.flagsByte = TraceMemoryFlag.toBits(flags);
			this.flags.clear();
			this.flags.addAll(flags);
			update(FLAGS_COLUMN);
			space.trace.updateViewsChangeRegionBlockFlags(this, lifespan);
		}
		space.trace.setChanged(
			new TraceChangeRecord<>(TraceMemoryRegionChangeType.CHANGED, space, this));
	}

	@SuppressWarnings("hiding")
	@Override
	public void addFlags(Collection<TraceMemoryFlag> flags) {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			this.flagsByte |= TraceMemoryFlag.toBits(flags);
			this.flags.addAll(flags);
			update(FLAGS_COLUMN);
			space.trace.updateViewsChangeRegionBlockFlags(this, lifespan);
		}
		space.trace.setChanged(
			new TraceChangeRecord<>(TraceMemoryRegionChangeType.CHANGED, space, this));
	}

	@SuppressWarnings("hiding")
	@Override
	public void clearFlags(Collection<TraceMemoryFlag> flags) {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			this.flagsByte &= ~TraceMemoryFlag.toBits(flags);
			this.flags.removeAll(flags);
			update(FLAGS_COLUMN);
			space.trace.updateViewsChangeRegionBlockFlags(this, lifespan);
		}
		space.trace.setChanged(
			new TraceChangeRecord<>(TraceMemoryRegionChangeType.CHANGED, space, this));
	}

	@Override
	public Set<TraceMemoryFlag> getFlags() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return Set.copyOf(flags);
		}
	}

	@Override
	public void delete() {
		space.deleteRegion(this);
	}
}
