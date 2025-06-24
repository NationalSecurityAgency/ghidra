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

import java.util.Collection;
import java.util.Objects;

import db.DBRecord;
import ghidra.program.model.address.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceSection;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.trace.util.TraceEvents;
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
	public DBTraceSection addSection(long snap, String sectionPath, String sectionName,
			AddressRange range) throws DuplicateNameException {
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
	public void setName(long snap, String name) {
		try (LockHold hold = LockHold.lock(space.manager.writeLock())) {
			if (Objects.equals(this.name, name)) {
				return;
			}
			this.name = name;
			update(NAME_COLUMN);
		}
		space.trace.setChanged(new TraceChangeRecord<>(TraceEvents.MODULE_CHANGED, null, this));
	}

	@Override
	public String getName(long snap) {
		try (LockHold hold = LockHold.lock(space.manager.readLock())) {
			return name;
		}
	}

	@Override
	public void setRange(long snap, AddressRange range) {
		try (LockHold hold = LockHold.lock(space.manager.writeLock())) {
			if (this.range.equals(range)) {
				return;
			}
			doSetRange(range);
		}
		space.trace.setChanged(new TraceChangeRecord<>(TraceEvents.MODULE_CHANGED, space, this));
	}

	@Override
	public AddressRange getRange(long snap) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return range;
		}
	}

	@Override
	public void setBase(long snap, Address base) {
		try (LockHold hold = LockHold.lock(space.manager.writeLock())) {
			setRange(snap, DBTraceUtils.toRange(base, range.getMaxAddress()));
		}
	}

	@Override
	public Address getBase(long snap) {
		try (LockHold hold = LockHold.lock(space.manager.readLock())) {
			return range.getMinAddress();
		}
	}

	@Override
	public void setMaxAddress(long snap, Address max) {
		try (LockHold hold = LockHold.lock(space.manager.writeLock())) {
			setRange(snap, DBTraceUtils.toRange(range.getMinAddress(), max));
		}
	}

	@Override
	public Address getMaxAddress(long snap) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return range.getMaxAddress();
		}
	}

	@Override
	public void setLength(long snap, long length) throws AddressOverflowException {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			Address base = range.getMinAddress();
			setRange(snap, DBTraceUtils.toRange(base, base.addNoWrap(length - 1)));
		}
	}

	@Override
	public long getLength(long snap) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return range.getLength();
		}
	}

	@Override
	public Collection<? extends DBTraceSection> getSections(long snap) {
		return getAllSections();
	}

	@Override
	public Collection<? extends DBTraceSection> getAllSections() {
		return space.manager.doGetSectionsByModuleId(getKey());
	}

	@Override
	public TraceSection getSectionByName(long snap, String sectionName) {
		return space.manager.doGetSectionByName(getKey(), sectionName);
	}

	@Override
	public void delete() {
		space.manager.doDeleteModule(this);
	}

	@Override
	public void remove(long snap) {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			if (snap <= lifespan.lmin()) {
				space.manager.doDeleteModule(this);
			}
			else if (snap <= lifespan.lmax()) {
				doSetLifespan(lifespan.withMax(snap - 1));
			}
		}
	}

	@Override
	public boolean isValid(long snap) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return lifespan.contains(snap);
		}
	}

	@Override
	public boolean isAlive(Lifespan span) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return lifespan.intersects(span);
		}
	}
}
