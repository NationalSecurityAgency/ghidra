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
import java.util.concurrent.locks.ReadWriteLock;

import db.DBHandle;
import ghidra.framework.data.OpenMode;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceManager;
import ghidra.trace.database.target.DBTraceObjectManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceBreakpointManager implements TraceBreakpointManager, DBTraceManager {
	protected final ReadWriteLock lock;
	protected final DBTrace trace;
	protected final DBTraceObjectManager objectManager;

	public DBTraceBreakpointManager(DBHandle dbh, OpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, DBTrace trace, DBTraceObjectManager objectManager)
			throws VersionException, IOException {
		this.lock = lock;
		this.trace = trace;
		this.objectManager = objectManager;
	}

	@Override
	public void dbError(IOException e) {
		trace.dbError(e);
	}

	@Override
	public void invalidateCache(boolean all) {
		// NOTE: This is only a wrapper around the object manager
	}

	@Override
	public TraceBreakpointLocation addBreakpoint(String path, Lifespan lifespan, AddressRange range,
			Collection<TraceThread> threads, Collection<TraceBreakpointKind> kinds, boolean enabled,
			String comment) throws DuplicateNameException {
		return objectManager.addBreakpoint(path, lifespan, range, threads, kinds, enabled, comment);
	}

	@Override
	public Collection<? extends TraceBreakpointSpec> getAllBreakpointSpecifications() {
		return objectManager.getAllObjects(TraceBreakpointSpec.class);
	}

	@Override
	public Collection<? extends TraceBreakpointLocation> getAllBreakpointLocations() {
		return objectManager.getAllObjects(TraceBreakpointLocation.class);
	}

	@Override
	public Collection<? extends TraceBreakpointSpec> getBreakpointSpecificationsByPath(
			String path) {
		return objectManager.getObjectsByPath(path, TraceBreakpointSpec.class);
	}

	@Override
	public Collection<? extends TraceBreakpointLocation> getBreakpointLocationsByPath(String path) {
		return objectManager.getObjectsByPath(path, TraceBreakpointLocation.class);
	}

	@Override
	public TraceBreakpointLocation getPlacedBreakpointByPath(long snap, String path) {
		return objectManager.getObjectByPath(snap, path, TraceBreakpointLocation.class);
	}

	@Override
	public Collection<? extends TraceBreakpointLocation> getBreakpointsAt(long snap,
			Address address) {
		return objectManager.getObjectsContaining(snap, address, TraceBreakpointLocation.KEY_RANGE,
			TraceBreakpointLocation.class);
	}

	@Override
	public Collection<? extends TraceBreakpointLocation> getBreakpointsIntersecting(Lifespan span,
			AddressRange range) {
		return objectManager.getObjectsIntersecting(span, range, TraceBreakpointLocation.KEY_RANGE,
			TraceBreakpointLocation.class);
	}
}
