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
import java.util.Collection;
import java.util.Collections;
import java.util.concurrent.locks.ReadWriteLock;

import com.google.common.collect.Range;

import db.DBHandle;
import ghidra.program.model.address.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapSpace;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager.DBTraceSpaceEntry;
import ghidra.trace.database.space.DBTraceSpaceBased;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.Trace.TraceBreakpointChangeType;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.database.DBCachedObjectIndex;
import ghidra.util.database.DBCachedObjectStoreFactory;
import ghidra.util.exception.VersionException;

public class DBTraceBreakpointSpace implements DBTraceSpaceBased {
	protected final DBTraceBreakpointManager manager;
	protected final DBHandle dbh;
	protected final AddressSpace space;
	protected final ReadWriteLock lock;
	protected final DBTrace trace;

	protected final DBTraceAddressSnapRangePropertyMapSpace<DBTraceBreakpoint, DBTraceBreakpoint> breakpointMapSpace;
	protected final DBCachedObjectIndex<String, DBTraceBreakpoint> breakpointsByPath;
	protected final Collection<TraceBreakpoint> breakpointView;

	public DBTraceBreakpointSpace(DBTraceBreakpointManager manager, DBHandle dbh,
			AddressSpace space, DBTraceSpaceEntry ent) throws VersionException, IOException {
		this.manager = manager;
		this.dbh = dbh;
		this.space = space;
		this.lock = manager.getLock();
		this.trace = manager.getTrace();

		DBCachedObjectStoreFactory factory = trace.getStoreFactory();

		long threadKey = ent.getThreadKey();
		assert threadKey == -1; // No breakpoints on registers
		breakpointMapSpace =
			new DBTraceAddressSnapRangePropertyMapSpace<DBTraceBreakpoint, DBTraceBreakpoint>(
				DBTraceBreakpoint.tableName(space, threadKey), factory, lock, space,
				DBTraceBreakpoint.class, (t, s, r) -> new DBTraceBreakpoint(this, t, s, r));
		breakpointsByPath =
			breakpointMapSpace.getUserIndex(String.class, DBTraceBreakpoint.PATH_COLUMN);
		breakpointView = Collections.unmodifiableCollection(breakpointMapSpace.values());
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

	protected DBTraceBreakpoint addBreakpoint(String path, Range<Long> lifespan, AddressRange range,
			Collection<TraceThread> threads, Collection<TraceBreakpointKind> kinds, boolean enabled,
			String comment) {
		// NOTE: thread here is not about address/register spaces.
		// It's about which thread to trap
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			DBTraceThreadManager threadManager = trace.getThreadManager();
			for (TraceThread t : threads) {
				threadManager.assertIsMine(t);
			}
			@SuppressWarnings({ "rawtypes", "unchecked" }) // checked by above assertIsMine
			Collection<DBTraceThread> dbThreads = (Collection) threads;
			DBTraceBreakpoint breakpoint =
				breakpointMapSpace.put(new ImmutableTraceAddressSnapRange(range, lifespan), null);
			breakpoint.set(path, path, dbThreads, kinds, enabled, comment);
			trace.setChanged(
				new TraceChangeRecord<>(TraceBreakpointChangeType.ADDED, this, breakpoint));
			return breakpoint;
		}
	}

	public Collection<? extends DBTraceBreakpoint> getAllBreakpoints() {
		return breakpointMapSpace.values();
	}

	public Collection<? extends DBTraceBreakpoint> getBreakpointsByPath(String name) {
		return Collections.unmodifiableCollection(breakpointsByPath.get(name));
	}

	public Collection<? extends DBTraceBreakpoint> getBreakpointsAt(long snap, Address address) {
		return Collections.unmodifiableCollection(
			breakpointMapSpace.reduce(TraceAddressSnapRangeQuery.at(address, snap)).values());
	}

	public Collection<? extends DBTraceBreakpoint> getBreakpointsIntersecting(Range<Long> span,
			AddressRange range) {
		return Collections.unmodifiableCollection(breakpointMapSpace.reduce(
			TraceAddressSnapRangeQuery.intersecting(range, span)).orderedValues());
	}

	public void deleteBreakpoint(DBTraceBreakpoint breakpoint) {
		breakpointMapSpace.deleteData(breakpoint);
		trace.setChanged(
			new TraceChangeRecord<>(TraceBreakpointChangeType.DELETED, this, breakpoint));
	}

	@Override
	public void invalidateCache() {
		breakpointMapSpace.invalidateCache();
	}
}
