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
import java.util.Collection;
import java.util.Collections;
import java.util.concurrent.locks.ReadWriteLock;

import db.DBHandle;
import ghidra.framework.data.OpenMode;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceManager;
import ghidra.trace.database.target.DBTraceObjectManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.modules.*;
import ghidra.util.LockHold;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceModuleManager implements TraceModuleManager, DBTraceManager {
	protected final ReadWriteLock lock;
	protected final DBTrace trace;
	protected final DBTraceObjectManager objectManager;

	public DBTraceModuleManager(DBHandle dbh, OpenMode openMode, ReadWriteLock lock,
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
	public TraceModule addModule(String modulePath, String moduleName, AddressRange range,
			Lifespan lifespan) throws DuplicateNameException {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			return doAddModule(modulePath, moduleName, range, lifespan);
		}
	}

	protected TraceModule doAddModule(String modulePath, String moduleName, AddressRange range,
			Lifespan lifespan) throws DuplicateNameException {
		return objectManager.addModule(modulePath, moduleName, lifespan, range);
	}

	protected Collection<? extends TraceModule> doGetModulesByPath(String modulePath) {
		return objectManager.getObjectsByPath(modulePath, TraceModule.class);
	}

	@Override
	public Collection<? extends TraceModule> getModulesByPath(String modulePath) {
		return Collections.unmodifiableCollection(doGetModulesByPath(modulePath));
	}

	@Override
	public TraceModule getLoadedModuleByPath(long snap, String modulePath) {
		return objectManager.getObjectByPath(snap, modulePath, TraceModule.class);
	}

	@Override
	public Collection<? extends TraceModule> getAllModules() {
		return objectManager.getAllObjects(TraceModule.class);
	}

	@Override
	public Collection<? extends TraceModule> getLoadedModules(long snap) {
		return objectManager.getObjectsAtSnap(snap, TraceModule.class);
	}

	@Override
	public Collection<? extends TraceModule> getModulesAt(long snap, Address address) {
		return objectManager.getObjectsContaining(snap, address, TraceModule.KEY_RANGE,
			TraceModule.class);
	}

	@Override
	public Collection<? extends TraceModule> getModulesIntersecting(Lifespan lifespan,
			AddressRange range) {
		return objectManager.getObjectsIntersecting(lifespan, range, TraceModule.KEY_RANGE,
			TraceModule.class);
	}

	@Override
	public Collection<? extends TraceSection> getSectionsAt(long snap, Address address) {
		return objectManager.getObjectsContaining(snap, address, TraceSection.KEY_RANGE,
			TraceSection.class);
	}

	@Override
	public Collection<? extends TraceSection> getSectionsIntersecting(Lifespan lifespan,
			AddressRange range) {
		return objectManager.getObjectsIntersecting(lifespan, range, TraceSection.KEY_RANGE,
			TraceSection.class);
	}

	@Override
	public Collection<? extends TraceSection> getAllSections() {
		return objectManager.getAllObjects(TraceSection.class);
	}

	protected Collection<? extends TraceSection> doGetSectionsByPath(String sectionPath) {
		return objectManager.getObjectsByPath(sectionPath, TraceSection.class);
	}

	@Override
	public Collection<? extends TraceSection> getSectionsByPath(String sectionPath) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return Collections.unmodifiableCollection(doGetSectionsByPath(sectionPath));
		}
	}

	@Override
	public TraceSection getLoadedSectionByPath(long snap, String sectionPath) {
		return objectManager.getObjectByPath(snap, sectionPath, TraceSection.class);
	}
}
