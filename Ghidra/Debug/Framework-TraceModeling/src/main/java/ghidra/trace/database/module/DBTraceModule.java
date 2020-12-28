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

import java.util.*;

import com.google.common.collect.Range;

import db.DBRecord;
import ghidra.program.model.address.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.model.Trace.TraceModuleChangeType;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceSection;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.DBObjectColumn;
import ghidra.util.database.annot.*;
import ghidra.util.exception.DuplicateNameException;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceModule extends AbstractDBTraceAddressSnapRangePropertyMapData<DBTraceModule>
		implements TraceModule {
	static final String TABLE_NAME = "Modules";

	static final String PATH_COLUMN_NAME = "Path";
	static final String NAME_COLUMN_NAME = "Name";

	@DBAnnotatedColumn(PATH_COLUMN_NAME)
	static DBObjectColumn PATH_COLUMN;
	@DBAnnotatedColumn(NAME_COLUMN_NAME)
	static DBObjectColumn NAME_COLUMN;

	static String tableName(AddressSpace space) {
		return DBTraceUtils.tableName(TABLE_NAME, space, -1, 0);
	}

	@DBAnnotatedField(column = PATH_COLUMN_NAME, indexed = true)
	String path;
	@DBAnnotatedField(column = NAME_COLUMN_NAME)
	String name;

	final DBTraceModuleSpace space;

	public DBTraceModule(DBTraceModuleSpace space,
			DBTraceAddressSnapRangePropertyMapTree<DBTraceModule, ?> tree,
			DBCachedObjectStore<?> store, DBRecord record) {
		super(tree, store, record);
		this.space = space;
	}

	@Override
	protected void setRecordValue(DBTraceModule value) {
		// Nothing. This is the record
	}

	@Override
	protected DBTraceModule getRecordValue() {
		return this;
	}

	void set(String path, String name) {
		this.path = path;
		this.name = name;
		update(PATH_COLUMN, NAME_COLUMN);
	}

	@Override
	public DBTrace getTrace() {
		return space.trace;
	}

	@Override
	public DBTraceSection addSection(String sectionPath, String sectionName, AddressRange range)
			throws DuplicateNameException {
		try (LockHold hold = LockHold.lock(space.manager.writeLock())) {
			return space.manager.doAddSection(this, sectionPath, sectionName, range);
		}
	}

	@Override
	public String getPath() {
		try (LockHold hold = LockHold.lock(space.manager.readLock())) {
			return path;
		}
	}

	@Override
	public void setName(String name) {
		try (LockHold hold = LockHold.lock(space.manager.writeLock())) {
			if (Objects.equals(this.name, name)) {
				return;
			}
			this.name = name;
			update(NAME_COLUMN);
		}
		space.trace.setChanged(new TraceChangeRecord<>(TraceModuleChangeType.CHANGED, null, this));
	}

	@Override
	public String getName() {
		try (LockHold hold = LockHold.lock(space.manager.readLock())) {
			return name;
		}
	}

	@Override
	public void setRange(AddressRange range) {
		try (LockHold hold = LockHold.lock(space.manager.writeLock())) {
			if (this.range.equals(range)) {
				return;
			}
			doSetRange(range);
		}
		space.trace.setChanged(new TraceChangeRecord<>(TraceModuleChangeType.CHANGED, space, this));
	}

	@Override
	public void setBase(Address base) {
		try (LockHold hold = LockHold.lock(space.manager.writeLock())) {
			setRange(DBTraceUtils.toRange(base, range.getMaxAddress()));
		}
	}

	@Override
	public Address getBase() {
		try (LockHold hold = LockHold.lock(space.manager.readLock())) {
			return range.getMinAddress();
		}
	}

	@Override
	public void setMaxAddress(Address max) {
		try (LockHold hold = LockHold.lock(space.manager.writeLock())) {
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
	public void setLength(long length) throws AddressOverflowException {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			Address base = range.getMinAddress();
			setRange(DBTraceUtils.toRange(base, base.addNoWrap(length - 1)));
		}
	}

	@Override
	public long getLength() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return range.getLength();
		}
	}

	@Override
	public void setLifespan(Range<Long> newLifespan) throws DuplicateNameException {
		Range<Long> oldLifespan;
		try (LockHold hold = LockHold.lock(space.manager.writeLock())) {
			space.manager.checkModulePathConflicts(this, path, newLifespan);
			ArrayList<? extends DBTraceSection> sections = new ArrayList<>(getSections());
			for (DBTraceSection traceSection : sections) {
				space.manager.checkSectionPathConflicts(traceSection, traceSection.getPath(),
					newLifespan);
			}
			oldLifespan = this.lifespan;
			doSetLifespan(newLifespan);
			for (DBTraceSection traceSection : sections) {
				traceSection.doSetLifespan(newLifespan);
			}
		}
		space.trace.setChanged(new TraceChangeRecord<>(TraceModuleChangeType.LIFESPAN_CHANGED,
			null, this, oldLifespan, newLifespan));
	}

	@Override
	public Range<Long> getLifespan() {
		try (LockHold hold = LockHold.lock(space.manager.readLock())) {
			return lifespan;
		}
	}

	@Override
	public void setLoadedSnap(long loadedSnap) throws DuplicateNameException {
		setLifespan(DBTraceUtils.toRange(loadedSnap, DBTraceUtils.upperEndpoint(lifespan)));
	}

	@Override
	public long getLoadedSnap() {
		try (LockHold hold = LockHold.lock(space.manager.readLock())) {
			return DBTraceUtils.lowerEndpoint(lifespan);
		}
	}

	@Override
	public void setUnloadedSnap(long unloadedSnap) throws DuplicateNameException {
		setLifespan(DBTraceUtils.toRange(DBTraceUtils.lowerEndpoint(lifespan), unloadedSnap));
	}

	@Override
	public long getUnloadedSnap() {
		try (LockHold hold = LockHold.lock(space.manager.readLock())) {
			return DBTraceUtils.upperEndpoint(lifespan);
		}
	}

	@Override
	public Collection<? extends DBTraceSection> getSections() {
		return space.manager.doGetSectionsByModuleId(getKey());
	}

	@Override
	public TraceSection getSectionByName(String sectionName) {
		return space.manager.doGetSectionByName(getKey(), sectionName);
	}

	@Override
	public void delete() {
		space.manager.doDeleteModule(this);
	}
}
