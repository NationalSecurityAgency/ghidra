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
import java.util.concurrent.locks.ReadWriteLock;

import com.google.common.collect.Range;

import ghidra.program.model.address.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapSpace;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.DBTraceSpaceBased;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.Trace.TraceModuleChangeType;
import ghidra.trace.model.Trace.TraceSectionChangeType;
import ghidra.trace.model.modules.TraceModuleSpace;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.database.DBCachedObjectIndex;
import ghidra.util.exception.VersionException;

public class DBTraceModuleSpace implements TraceModuleSpace, DBTraceSpaceBased {
	protected final DBTraceModuleManager manager;
	protected final AddressSpace space;
	protected final ReadWriteLock lock;
	protected final DBTrace trace;

	protected final DBTraceAddressSnapRangePropertyMapSpace<DBTraceModule, DBTraceModule> moduleMapSpace;
	protected final DBCachedObjectIndex<String, DBTraceModule> modulesByPath;
	protected final Collection<DBTraceModule> moduleView;

	protected final DBTraceAddressSnapRangePropertyMapSpace<DBTraceSection, DBTraceSection> sectionMapSpace;
	protected final DBCachedObjectIndex<Long, DBTraceSection> sectionsByModuleKey;
	protected final DBCachedObjectIndex<String, DBTraceSection> sectionsByPath;
	protected final Collection<DBTraceSection> sectionView;

	public DBTraceModuleSpace(DBTraceModuleManager manager, AddressSpace space)
			throws VersionException, IOException {
		this.manager = manager;
		this.space = space;
		this.lock = manager.getLock();
		this.trace = manager.getTrace();

		this.moduleMapSpace = new DBTraceAddressSnapRangePropertyMapSpace<>(
			DBTraceModule.tableName(space), trace.getStoreFactory(), lock, space,
			DBTraceModule.class, (t, s, r) -> new DBTraceModule(this, t, s, r));
		this.modulesByPath = moduleMapSpace.getUserIndex(String.class, DBTraceModule.PATH_COLUMN);
		this.moduleView = Collections.unmodifiableCollection(moduleMapSpace.values());

		this.sectionMapSpace = new DBTraceAddressSnapRangePropertyMapSpace<>(
			DBTraceSection.tableName(space), trace.getStoreFactory(), lock, space,
			DBTraceSection.class, (t, s, r) -> new DBTraceSection(this, t, s, r));
		this.sectionsByModuleKey =
			sectionMapSpace.getUserIndex(long.class, DBTraceSection.MODULE_COLUMN);
		this.sectionsByPath =
			sectionMapSpace.getUserIndex(String.class, DBTraceSection.PATH_COLUMN);
		this.sectionView = Collections.unmodifiableCollection(sectionMapSpace.values());
	}

	@Override
	public DBTraceThread getThread() {
		return null;
	}

	@Override
	public int getFrameLevel() {
		return 0;
	}

	@Override
	public void invalidateCache() {
		moduleMapSpace.invalidateCache();
		sectionMapSpace.invalidateCache();
	}

	@Override
	public AddressSpace getAddressSpace() {
		return space;
	}

	protected DBTraceModule doAddModule(String modulePath, String moduleName, AddressRange range,
			Range<Long> lifespan) {
		DBTraceModule module = moduleMapSpace
				.put(new ImmutableTraceAddressSnapRange(range, lifespan), null);
		module.set(modulePath, moduleName);
		trace.setChanged(new TraceChangeRecord<>(TraceModuleChangeType.ADDED, null, module));
		return module;
	}

	@Override
	public Collection<? extends DBTraceModule> getAllModules() {
		return moduleView;
	}

	protected Collection<? extends DBTraceModule> doGetModulesByPath(String modulePath) {
		return modulesByPath.get(modulePath);
	}

	@Override
	public Collection<? extends DBTraceModule> getLoadedModules(long snap) {
		return Collections.unmodifiableCollection(
			moduleMapSpace.reduce(TraceAddressSnapRangeQuery.atSnap(snap, space)).values());
	}

	@Override
	public Collection<? extends DBTraceModule> getModulesAt(long snap, Address address) {
		return Collections.unmodifiableCollection(
			moduleMapSpace.reduce(TraceAddressSnapRangeQuery.at(address, snap)).values());
	}

	@Override
	public Collection<? extends DBTraceModule> getModulesIntersecting(Range<Long> lifespan,
			AddressRange range) {
		return Collections.unmodifiableCollection(
			moduleMapSpace.reduce(TraceAddressSnapRangeQuery.intersecting(range, lifespan))
					.values());
	}

	public DBTraceSection doAddSection(DBTraceModule module, String sectionPath, String sectionName,
			AddressRange range) {
		DBTraceSection section = sectionMapSpace
				.put(new ImmutableTraceAddressSnapRange(range, module.getLifespan()), null);
		section.set(module, sectionPath, sectionName);
		trace.setChanged(new TraceChangeRecord<>(TraceSectionChangeType.ADDED, null, section));
		return section;
	}

	@Override
	public Collection<? extends DBTraceSection> getAllSections() {
		return sectionView;
	}

	@Override
	public Collection<? extends DBTraceSection> getSectionsAt(long snap, Address address) {
		return Collections.unmodifiableCollection(
			sectionMapSpace.reduce(TraceAddressSnapRangeQuery.at(address, snap)).values());
	}

	@Override
	public Collection<? extends DBTraceSection> getSectionsIntersecting(Range<Long> lifespan,
			AddressRange range) {
		return Collections.unmodifiableCollection(
			sectionMapSpace.reduce(TraceAddressSnapRangeQuery.intersecting(range, lifespan))
					.values());
	}

	public Collection<? extends DBTraceSection> doGetSectionsByModuleId(long key) {
		return sectionsByModuleKey.get(key);
	}

	public DBTraceSection doGetSectionByName(long moduleKey, String sectionName) {
		for (DBTraceSection section : sectionsByModuleKey.get(moduleKey)) {
			if (!Objects.equals(section.getName(), sectionName)) {
				continue;
			}
			return section;
		}
		return null;
	}

	public Collection<? extends DBTraceSection> doGetSectionsByPath(String sectionPath) {
		return sectionsByPath.get(sectionPath);
	}

	public DBTraceModule doGetModuleById(long moduleKey) {
		return moduleMapSpace.getDataByKey(moduleKey);
	}
}
