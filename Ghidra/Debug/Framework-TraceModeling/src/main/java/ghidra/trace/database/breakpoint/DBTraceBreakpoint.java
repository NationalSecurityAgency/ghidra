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
package ghidra.trace.database.breakpoint;

import java.io.IOException;
import java.util.*;

import db.DBRecord;
import ghidra.pcode.exec.SleighUtils;
import ghidra.program.model.address.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.trace.util.TraceEvents;
import ghidra.util.LockHold;
import ghidra.util.Msg;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.DBObjectColumn;
import ghidra.util.database.annot.*;
import ghidra.util.exception.DuplicateNameException;

@DBAnnotatedObjectInfo(version = 1)
public class DBTraceBreakpoint
		extends AbstractDBTraceAddressSnapRangePropertyMapData<DBTraceBreakpoint>
		implements TraceBreakpoint {
	protected static final String TABLE_NAME = "Breakpoints";

	private static final byte ENABLED_MASK = (byte) (1 << 7);
	private static final byte EMU_ENABLED_MASK = (byte) (1 << 6);

	static final String PATH_COLUMN_NAME = "Path";
	static final String NAME_COLUMN_NAME = "Name";
	static final String THREADS_COLUMN_NAME = "Threads";
	static final String FLAGS_COLUMN_NAME = "Flags";
	static final String COMMENT_COLUMN_NAME = "Comment";
	static final String SLEIGH_COLUMN_NAME = "Sleigh";

	@DBAnnotatedColumn(PATH_COLUMN_NAME)
	static DBObjectColumn PATH_COLUMN;
	@DBAnnotatedColumn(NAME_COLUMN_NAME)
	static DBObjectColumn NAME_COLUMN;
	@DBAnnotatedColumn(THREADS_COLUMN_NAME)
	static DBObjectColumn THREADS_COLUMN;
	@DBAnnotatedColumn(FLAGS_COLUMN_NAME)
	static DBObjectColumn FLAGS_COLUMN;
	@DBAnnotatedColumn(COMMENT_COLUMN_NAME)
	static DBObjectColumn COMMENT_COLUMN;
	@DBAnnotatedColumn(SLEIGH_COLUMN_NAME)
	static DBObjectColumn SLEIGH_COLUMN;

	protected static String tableName(AddressSpace space, long threadKey) {
		return DBTraceUtils.tableName(TABLE_NAME, space, threadKey, 0);
	}

	@DBAnnotatedField(column = PATH_COLUMN_NAME, indexed = true)
	private String path;
	@DBAnnotatedField(column = NAME_COLUMN_NAME)
	private String name;
	@DBAnnotatedField(column = THREADS_COLUMN_NAME)
	private long[] threadKeys;
	@DBAnnotatedField(column = FLAGS_COLUMN_NAME)
	private byte flagsByte;
	@DBAnnotatedField(column = COMMENT_COLUMN_NAME)
	private String comment;
	@DBAnnotatedField(column = SLEIGH_COLUMN_NAME)
	private String emuSleigh;

	private final Set<TraceBreakpointKind> kinds = EnumSet.noneOf(TraceBreakpointKind.class);
	private final Set<TraceBreakpointKind> kindsView = Collections.unmodifiableSet(kinds);
	private boolean enabled;
	private boolean emuEnabled;

	protected final DBTraceBreakpointSpace space;

	public DBTraceBreakpoint(DBTraceBreakpointSpace space,
			DBTraceAddressSnapRangePropertyMapTree<DBTraceBreakpoint, ?> tree,
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
		doFresh();
	}

	private void doFresh() {
		kinds.clear();
		for (TraceBreakpointKind k : TraceBreakpointKind.values()) {
			if ((flagsByte & k.getBits()) != 0) {
				kinds.add(k);
			}
		}
		enabled = (flagsByte & ENABLED_MASK) != 0;
		emuEnabled = (flagsByte & EMU_ENABLED_MASK) != 0;
	}

	@Override
	public DBTrace getTrace() {
		return space.trace;
	}

	@Override
	protected void setRecordValue(DBTraceBreakpoint value) {
		// Nothing: record is the value
	}

	@Override
	protected DBTraceBreakpoint getRecordValue() {
		return this;
	}

	public void set(String path, String name, Collection<TraceThread> threads,
			Collection<TraceBreakpointKind> kinds, boolean enabled, boolean emuEnabled,
			String comment) {
		// TODO: Check that the threads exist and that each's lifespan covers the breakpoint's
		// TODO: This would require additional validation any time those are updated
		// TODO: For efficiency, would also require index of breakpoints by thread
		this.path = path;
		this.name = name;
		if (!(threads instanceof Set<?>)) {
			threads = Set.copyOf(threads);
		}
		this.threadKeys = new long[threads.size()];
		int i = 0;
		for (TraceThread t : threads) {
			this.threadKeys[i++] = t.getKey();
		}
		this.flagsByte = 0;
		this.kinds.clear();
		for (TraceBreakpointKind k : kinds) {
			this.flagsByte |= k.getBits();
			this.kinds.add(k);
		}
		if (enabled) {
			this.flagsByte |= ENABLED_MASK;
		}
		if (emuEnabled) {
			this.flagsByte |= EMU_ENABLED_MASK;
		}
		this.comment = comment;
		update(PATH_COLUMN, NAME_COLUMN, THREADS_COLUMN, FLAGS_COLUMN, COMMENT_COLUMN);
		this.enabled = enabled;
		this.emuEnabled = emuEnabled;
		// Msg.debug(this, "trace: breakpoint " + this + " enabled=" + enabled + ", because set");
	}

	public void set(String path, String name, long[] threadKeys,
			byte flagsByte, String comment) {
		this.path = path;
		this.name = name;
		this.threadKeys = Arrays.copyOf(threadKeys, threadKeys.length);
		this.flagsByte = flagsByte;
		this.comment = comment;
		update(PATH_COLUMN, NAME_COLUMN, THREADS_COLUMN, FLAGS_COLUMN, COMMENT_COLUMN);
		doFresh();
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
		}
		space.trace
				.setChanged(new TraceChangeRecord<>(TraceEvents.BREAKPOINT_CHANGED, space, this));

	}

	@Override
	public String getName() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return name;
		}
	}

	@Override
	public Set<TraceThread> getThreads() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			if (threadKeys.length == 0) {
				return Set.of();
			}
			// NOTE: Caching this result could get hairy if any threads are invalidated....
			Set<TraceThread> threads = new LinkedHashSet<>(threadKeys.length);
			DBTraceThreadManager threadManager = space.trace.getThreadManager();
			for (int i = 0; i < threadKeys.length; i++) {
				TraceThread t = threadManager.getThread(threadKeys[i]);
				if (t == null) {
					Msg.warn(this, "Thread " + threadKeys[i] +
						" has been deleted since creating this breakpoint.");
				}
				threads.add(t);
			}
			return Collections.unmodifiableSet(threads);
		}
	}

	@Override
	public AddressRange getRange() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return range;
		}
	}

	@Override
	public Address getMinAddress() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return range.getMinAddress();
		}
	}

	@Override
	public Address getMaxAddress() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return range.getMaxAddress();
		}
	}

	@Override
	public long getLength() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return range.getLength();
		}
	}

	protected void setLifespan(Lifespan newLifespan) throws DuplicateNameException {
		Lifespan oldLifespan;
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			space.manager.checkDuplicatePath(this, path, newLifespan);
			oldLifespan = lifespan;
			doSetLifespan(newLifespan);
		}
		space.trace.setChanged(new TraceChangeRecord<>(TraceEvents.BREAKPOINT_LIFESPAN_CHANGED,
			space, this, oldLifespan, newLifespan));
	}

	@Override
	public Lifespan getLifespan() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return lifespan;
		}
	}

	@Override
	public boolean isAlive(long snap) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return lifespan.contains(snap);
		}
	}

	@Override
	public long getPlacedSnap() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return lifespan.lmin();
		}
	}

	@Override
	public void setClearedSnap(long clearedSnap) throws DuplicateNameException {
		setLifespan(Lifespan.span(getPlacedSnap(), clearedSnap));
	}

	@Override
	public long getClearedSnap() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return lifespan.lmax();
		}
	}

	protected DBTraceBreakpoint doCopy() {
		DBTraceBreakpoint breakpoint = space.breakpointMapSpace.put(this, null);
		breakpoint.set(path, name, threadKeys, flagsByte, comment);
		return breakpoint;
	}

	@Override
	public DBTraceBreakpoint splitAndSet(long snap, boolean en,
			Collection<TraceBreakpointKind> kinds) {
		DBTraceBreakpoint that;
		Lifespan oldLifespan = null;
		Lifespan newLifespan = null;
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			if (!lifespan.contains(snap)) {
				throw new IllegalArgumentException("snap = " + snap);
			}
			if (flagsByte == computeFlagsByte(en, kinds)) {
				return this;
			}
			if (snap == getPlacedSnap()) {
				this.doSetFlags(en, kinds);
				that = this;
			}
			else {
				that = doCopy();
				that.doSetLifespan(Lifespan.span(snap, getClearedSnap()));
				that.doSetFlags(en, kinds);
				oldLifespan = lifespan;
				newLifespan = Lifespan.span(getPlacedSnap(), snap - 1);
				this.doSetLifespan(newLifespan);
			}
		}
		if (that == this) {
			space.trace.setChanged(
				new TraceChangeRecord<>(TraceEvents.BREAKPOINT_CHANGED, space, this));
		}
		else {
			// Yes, issue ADDED, before LIFESPAN_CHANGED, as noted in docs
			space.trace
					.setChanged(new TraceChangeRecord<>(TraceEvents.BREAKPOINT_ADDED, space, that));
			space.trace.setChanged(
				new TraceChangeRecord<>(TraceEvents.BREAKPOINT_LIFESPAN_CHANGED, space, this,
					Objects.requireNonNull(oldLifespan), Objects.requireNonNull(newLifespan)));
		}
		return that;
	}

	protected static byte computeFlagsByte(boolean enabled, Collection<TraceBreakpointKind> kinds) {
		byte flags = 0;
		for (TraceBreakpointKind k : kinds) {
			flags |= k.getBits();
		}
		if (enabled) {
			flags |= ENABLED_MASK;
		}
		return flags;
	}

	protected void doSetFlags(boolean enabled, Collection<TraceBreakpointKind> kinds) {
		this.flagsByte = computeFlagsByte(enabled, kinds);
		this.kinds.clear();
		this.kinds.addAll(kinds);
		this.enabled = enabled;
		// Msg.debug(this,
		// 	"trace: breakpoint " + this + " enabled=" + enabled + ", because doSetFlags");
		update(FLAGS_COLUMN);
	}

	protected void doSetEnabled(boolean enabled) {
		this.enabled = enabled;
		// Msg.debug(this,
		//	"trace: breakpoint " + this + " enabled=" + enabled + ", because doSetEnabled");
		if (enabled) {
			flagsByte |= ENABLED_MASK;
		}
		else {
			flagsByte &= ~ENABLED_MASK;
		}
		update(FLAGS_COLUMN);
	}

	protected void doSetEmuEnabled(boolean emuEnabled) {
		this.emuEnabled = emuEnabled;
		if (emuEnabled) {
			flagsByte |= EMU_ENABLED_MASK;
		}
		else {
			flagsByte &= ~EMU_ENABLED_MASK;
		}
		update(FLAGS_COLUMN);
	}

	protected void doSetKinds(Collection<TraceBreakpointKind> kinds) {
		for (TraceBreakpointKind k : TraceBreakpointKind.values()) {
			if (kinds.contains(k)) {
				this.flagsByte |= k.getBits();
				this.kinds.add(k);
			}
			else {
				this.flagsByte &= ~k.getBits();
				this.kinds.remove(k);
			}
		}
		update(FLAGS_COLUMN);
	}

	@Override
	public void setEnabled(boolean enabled) {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			doSetEnabled(enabled);
		}
		space.trace
				.setChanged(new TraceChangeRecord<>(TraceEvents.BREAKPOINT_CHANGED, space, this));
	}

	@Override
	public boolean isEnabled(long snap) {
		// NB. Only object mode supports per-snap enablement
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return enabled;
		}
	}

	@Override
	public void setEmuEnabled(boolean enabled) {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			doSetEmuEnabled(enabled);
		}
		space.trace
				.setChanged(new TraceChangeRecord<>(TraceEvents.BREAKPOINT_CHANGED, space, this));
	}

	@Override
	public boolean isEmuEnabled(long snap) {
		// NB. Only object mode support per-snap emu-enablement
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return emuEnabled;
		}
	}

	@Override
	public void setKinds(Collection<TraceBreakpointKind> kinds) {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			doSetKinds(kinds);
		}
		space.trace
				.setChanged(new TraceChangeRecord<>(TraceEvents.BREAKPOINT_CHANGED, space, this));
	}

	@Override
	public Set<TraceBreakpointKind> getKinds() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return kindsView;
		}
	}

	@Override
	public void setComment(String comment) {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			this.comment = comment;
			update(COMMENT_COLUMN);
		}
		space.trace
				.setChanged(new TraceChangeRecord<>(TraceEvents.BREAKPOINT_CHANGED, space, this));
	}

	@Override
	public String getComment() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return comment;
		}
	}

	@Override
	public void setEmuSleigh(String emuSleigh) {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			if (emuSleigh == null || SleighUtils.UNCONDITIONAL_BREAK.equals(emuSleigh)) {
				this.emuSleigh = null;
			}
			else {
				this.emuSleigh = emuSleigh.trim();
			}
			update(SLEIGH_COLUMN);
		}
		space.trace
				.setChanged(new TraceChangeRecord<>(TraceEvents.BREAKPOINT_CHANGED, space, this));
	}

	@Override
	public String getEmuSleigh() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return emuSleigh == null || emuSleigh.isBlank() ? SleighUtils.UNCONDITIONAL_BREAK
					: emuSleigh;
		}
	}

	@Override
	public void delete() {
		space.deleteBreakpoint(this);
	}

	@Override
	public boolean isValid(long snap) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return lifespan.contains(snap);
		}
	}
}
