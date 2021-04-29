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
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;

import com.google.common.collect.Range;

import db.DBHandle;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager;
import ghidra.trace.database.space.DBTraceDelegatingManager;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.LockHold;
import ghidra.util.database.DBOpenMode;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceBreakpointManager
		extends AbstractDBTraceSpaceBasedManager<DBTraceBreakpointSpace, DBTraceBreakpointSpace>
		implements TraceBreakpointManager, DBTraceDelegatingManager<DBTraceBreakpointSpace> {
	protected static final String NAME = "Breakpoint";

	public DBTraceBreakpointManager(DBHandle dbh, DBOpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, Language baseLanguage, DBTrace trace,
			DBTraceThreadManager threadManager) throws VersionException, IOException {
		super(NAME, dbh, openMode, lock, monitor, baseLanguage, trace, threadManager);

		loadSpaces();
	}

	@Override
	protected DBTraceBreakpointSpace createSpace(AddressSpace space, DBTraceSpaceEntry ent)
			throws VersionException, IOException {
		return new DBTraceBreakpointSpace(this, dbh, space, ent);
	}

	@Override
	protected DBTraceBreakpointSpace createRegisterSpace(AddressSpace space, DBTraceThread thread,
			DBTraceSpaceEntry ent) throws VersionException, IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public DBTraceBreakpointSpace getForSpace(AddressSpace space, boolean createIfAbsent) {
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

	protected void checkDuplicatePath(DBTraceBreakpoint ignore, String path, Range<Long> lifespan)
			throws DuplicateNameException {
		for (DBTraceBreakpoint pc : getBreakpointsByPath(path)) {
			if (pc == ignore) {
				continue;
			}
			if (!DBTraceUtils.intersect(lifespan, pc.getLifespan())) {
				continue;
			}
			throw new DuplicateNameException("A breakpoint having path '" + path +
				"' already exists within an overlapping snap");
		}
	}

	@Override
	public TraceBreakpoint addBreakpoint(String path, Range<Long> lifespan, AddressRange range,
			Collection<TraceThread> threads, Collection<TraceBreakpointKind> kinds, boolean enabled,
			String comment) throws DuplicateNameException {
		checkDuplicatePath(null, path, lifespan);
		return delegateWrite(range.getAddressSpace(),
			m -> m.addBreakpoint(path, lifespan, range, threads, kinds, enabled, comment));
	}

	@Override
	public Collection<? extends DBTraceBreakpoint> getAllBreakpoints() {
		return delegateCollection(getActiveMemorySpaces(), m -> m.getAllBreakpoints());
	}

	@Override
	public Collection<? extends DBTraceBreakpoint> getBreakpointsByPath(String path) {
		return delegateCollection(getActiveMemorySpaces(), m -> m.getBreakpointsByPath(path));
	}

	@Override
	public TraceBreakpoint getPlacedBreakpointByPath(long snap, String path) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return getBreakpointsByPath(path)
					.stream()
					.filter(b -> b.getLifespan().contains(snap))
					.findAny()
					.orElse(null);
		}
	}

	@Override
	public Collection<? extends DBTraceBreakpoint> getBreakpointsAt(long snap, Address address) {
		return delegateRead(address.getAddressSpace(), m -> m.getBreakpointsAt(snap, address),
			Collections.emptyList());
	}

	@Override
	public Collection<? extends DBTraceBreakpoint> getBreakpointsIntersecting(Range<Long> span,
			AddressRange range) {
		return delegateRead(range.getAddressSpace(), m -> m.getBreakpointsIntersecting(span, range),
			Collections.emptyList());
	}
}
