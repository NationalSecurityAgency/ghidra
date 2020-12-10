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
import java.util.*;
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
import ghidra.trace.model.Trace.TraceModuleChangeType;
import ghidra.trace.model.modules.TraceModuleManager;
import ghidra.trace.model.modules.TraceSection;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.database.DBOpenMode;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceModuleManager
		extends AbstractDBTraceSpaceBasedManager<DBTraceModuleSpace, DBTraceModuleSpace>
		implements TraceModuleManager, DBTraceDelegatingManager<DBTraceModuleSpace> {
	public static final String NAME = "Module";

	public DBTraceModuleManager(DBHandle dbh, DBOpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, Language baseLanguage, DBTrace trace)
			throws VersionException, IOException {
		super(NAME, dbh, openMode, lock, monitor, baseLanguage, trace, null);
		loadSpaces();
	}

	@Override
	public DBTraceModuleSpace getForSpace(AddressSpace space, boolean createIfAbsent) {
		return super.getForSpace(space, createIfAbsent);
	}

	@Override
	protected DBTraceModuleSpace getForRegisterSpace(TraceThread thread, int frameLevel,
			boolean createIfAbsent) {
		throw new UnsupportedOperationException();
	}

	protected void checkModulePathConflicts(DBTraceModule ignore, String modulePath,
			Range<Long> moduleLifespan) throws DuplicateNameException {
		for (DBTraceModule pc : doGetModulesByPath(modulePath)) {
			if (pc == ignore) {
				continue;
			}
			if (!DBTraceUtils.intersect(pc.getLifespan(), moduleLifespan)) {
				continue;
			}
			throw new DuplicateNameException("Module with path '" +
				modulePath + "' already exists within an overlapping snap");
		}
	}

	protected void checkSectionPathConflicts(DBTraceSection ignore, String sectionPath,
			Range<Long> moduleLifespan) throws DuplicateNameException {
		Collection<? extends DBTraceSection> pathConflicts = doGetSectionsByPath(sectionPath);
		for (DBTraceSection pc : pathConflicts) {
			if (pc == ignore) {
				continue;
			}
			if (!DBTraceUtils.intersect(pc.getLifespan(), moduleLifespan)) {
				continue;
			}
			throw new DuplicateNameException("Section with path '" + sectionPath +
				"' already exists within an overlapping snap");
		}
	}

	@Override
	public DBTraceModule addModule(String modulePath, String moduleName, AddressRange range,
			Range<Long> lifespan) throws DuplicateNameException {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			return doAddModule(modulePath, moduleName, range, lifespan);
		}
	}

	protected DBTraceModule doAddModule(String modulePath, String moduleName, AddressRange range,
			Range<Long> lifespan) throws DuplicateNameException {
		checkModulePathConflicts(null, modulePath, lifespan);
		return delegateWrite(range.getAddressSpace(),
			m -> m.doAddModule(modulePath, moduleName, range, lifespan));
	}

	protected Collection<? extends DBTraceModule> doGetModulesByPath(String modulePath) {
		return delegateCollection(memSpaces.values(), m -> m.doGetModulesByPath(modulePath));
	}

	@Override
	public Collection<? extends DBTraceModule> getModulesByPath(String modulePath) {
		return Collections.unmodifiableCollection(doGetModulesByPath(modulePath));
	}

	@Override
	public DBTraceModule getLoadedModuleByPath(long snap, String modulePath) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return doGetModulesByPath(modulePath)
					.stream()
					.filter(m -> m.getLifespan().contains(snap))
					.findAny()
					.orElse(null);
		}
	}

	@Override
	public Collection<? extends DBTraceModule> getAllModules() {
		return delegateCollection(memSpaces.values(), m -> m.getAllModules());
	}

	@Override
	public Collection<? extends DBTraceModule> getLoadedModules(long snap) {
		return delegateCollection(memSpaces.values(), m -> m.getLoadedModules(snap));
	}

	@Override
	public Collection<? extends DBTraceModule> getModulesAt(long snap, Address address) {
		return delegateRead(address.getAddressSpace(),
			m -> m.getModulesAt(snap, address), Set.of());
	}

	@Override
	public Collection<? extends DBTraceModule> getModulesIntersecting(Range<Long> lifespan,
			AddressRange range) {
		return delegateRead(range.getAddressSpace(),
			m -> m.getModulesIntersecting(lifespan, range), Set.of());
	}

	@Override
	public ReadWriteLock getLock() {
		return lock;
	}

	@Override
	public Collection<? extends DBTraceSection> getSectionsAt(long snap, Address address) {
		return delegateRead(address.getAddressSpace(),
			m -> m.getSectionsAt(snap, address), Set.of());
	}

	@Override
	public Collection<? extends DBTraceSection> getSectionsIntersecting(Range<Long> lifespan,
			AddressRange range) {
		return delegateRead(range.getAddressSpace(),
			m -> m.getSectionsIntersecting(lifespan, range), Set.of());
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
	protected DBTraceModuleSpace createSpace(AddressSpace space, DBTraceSpaceEntry ent)
			throws VersionException, IOException {
		return new DBTraceModuleSpace(this, space);
	}

	@Override
	protected DBTraceModuleSpace createRegisterSpace(AddressSpace space, DBTraceThread thread,
			DBTraceSpaceEntry ent) throws VersionException, IOException {
		throw new AssertionError();
	}

	protected DBTraceSection doAddSection(DBTraceModule module, String sectionPath,
			String sectionName, AddressRange range) throws DuplicateNameException {
		checkSectionPathConflicts(null, sectionPath, module.getLifespan());
		DBTraceSection nameConflicts = doGetSectionByName(module.getKey(), sectionName);
		if (nameConflicts != null) {
			throw new DuplicateNameException(
				"Section with name '" + sectionName + "' already exists");
		}
		return delegateWrite(range.getAddressSpace(),
			m -> m.doAddSection(module, sectionPath, sectionName, range));
	}

	@Override
	public Collection<? extends DBTraceSection> getAllSections() {
		return delegateCollection(memSpaces.values(), m -> m.getAllSections());
	}

	protected Collection<? extends DBTraceSection> doGetSectionsByModuleId(long key) {
		return delegateCollection(memSpaces.values(), m -> m.doGetSectionsByModuleId(key));
	}

	protected Collection<? extends DBTraceSection> doGetSectionsByPath(String sectionPath) {
		return delegateCollection(memSpaces.values(), m -> m.doGetSectionsByPath(sectionPath));
	}

	@Override
	public Collection<? extends DBTraceSection> getSectionsByPath(String sectionPath) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return Collections.unmodifiableCollection(doGetSectionsByPath(sectionPath));
		}
	}

	@Override
	public TraceSection getLoadedSectionByPath(long snap, String sectionPath) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return doGetSectionsByPath(sectionPath)
					.stream()
					.filter(s -> s.getLifespan().contains(snap))
					.findAny()
					.orElse(null);
		}
	}

	protected DBTraceSection doGetSectionByName(long moduleKey, String sectionName) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return delegateFirst(memSpaces.values(),
				m -> m.doGetSectionByName(moduleKey, sectionName));
		}
	}

	protected void doDeleteModule(DBTraceModule module) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			for (DBTraceSection section : new ArrayList<>(
				doGetSectionsByModuleId(module.getKey()))) {
				section.space.sectionMapSpace.deleteData(section);
				// NOTE: Don't send section events. Module event should suffice.
			}
			module.space.moduleMapSpace.deleteData(module);
		}
		trace.setChanged(new TraceChangeRecord<>(TraceModuleChangeType.DELETED, null, module));
	}
}
