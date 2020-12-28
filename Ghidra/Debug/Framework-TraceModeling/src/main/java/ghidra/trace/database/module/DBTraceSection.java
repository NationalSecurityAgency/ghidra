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
import java.util.Objects;

import com.google.common.collect.Range;

import db.DBRecord;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceSectionChangeType;
import ghidra.trace.model.modules.TraceSection;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.DBObjectColumn;
import ghidra.util.database.annot.*;
import ghidra.util.exception.DuplicateNameException;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceSection extends AbstractDBTraceAddressSnapRangePropertyMapData<DBTraceSection>
		implements TraceSection {
	private static final String TABLE_NAME = "Sections";

	static final String MODULE_COLUMN_NAME = "Module";
	static final String PATH_COLUMN_NAME = "Path";
	static final String NAME_COLUMN_NAME = "Name";

	@DBAnnotatedColumn(MODULE_COLUMN_NAME)
	static DBObjectColumn MODULE_COLUMN;
	@DBAnnotatedColumn(PATH_COLUMN_NAME)
	static DBObjectColumn PATH_COLUMN;
	@DBAnnotatedColumn(NAME_COLUMN_NAME)
	static DBObjectColumn NAME_COLUMN;

	static String tableName(AddressSpace space) {
		return DBTraceUtils.tableName(TABLE_NAME, space, -1, 0);
	}

	@DBAnnotatedField(column = MODULE_COLUMN_NAME, indexed = true)
	private long moduleKey;
	@DBAnnotatedField(column = PATH_COLUMN_NAME, indexed = true)
	private String path;
	@DBAnnotatedField(column = NAME_COLUMN_NAME)
	private String name;

	final DBTraceModuleSpace space;

	private DBTraceModule module;

	public DBTraceSection(DBTraceModuleSpace space,
			DBTraceAddressSnapRangePropertyMapTree<DBTraceSection, ?> tree,
			DBCachedObjectStore<?> store, DBRecord record) {
		super(tree, store, record);
		this.space = space;
	}

	@Override
	protected void setRecordValue(DBTraceSection value) {
		// Nothing. This is the record
	}

	@Override
	protected DBTraceSection getRecordValue() {
		return this;
	}

	@Override
	protected void fresh(boolean created) throws IOException {
		super.fresh(created);
		if (created) {
			return;
		}
		/**
		 * TODO: This may cause a problem when modules span multiple spaces. Well, the whole "unique
		 * path" thing may already be a problem in that case, since each module is allowed one
		 * address range. Maybe unique names within spaces only, and somehow a module comprises all
		 * its entries among the spaces.
		 */
		this.module = space.doGetModuleById(moduleKey);
	}

	void set(DBTraceModule module, String path, String name) {
		this.moduleKey = module.getKey();
		this.path = path;
		this.name = name;
		update(MODULE_COLUMN, PATH_COLUMN, NAME_COLUMN);

		this.module = module;
	}

	@Override
	public Trace getTrace() {
		return space.trace;
	}

	@Override
	public DBTraceModule getModule() {
		return module;
	}

	@Override // Expose to this package
	@SuppressWarnings("hiding")
	protected void doSetLifespan(Range<Long> lifespan) {
		super.doSetLifespan(lifespan);
	}

	@Override
	public String getPath() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return path;
		}
	}

	@Override
	public void setName(String name) throws DuplicateNameException {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			if (Objects.equals(this.name, name)) {
				return;
			}
			DBTraceSection exists = space.manager.doGetSectionByName(moduleKey, name);
			if (exists != null) {
				throw new DuplicateNameException(name + " (in " + module + ")");
			}
			this.name = name;
			update(NAME_COLUMN);
			module.space.trace.setChanged(
				new TraceChangeRecord<>(TraceSectionChangeType.CHANGED, null, this));
		}
	}

	@Override
	public String getName() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return name;
		}
	}

	@Override
	public void delete() {
		space.sectionMapSpace.deleteData(this);
		space.trace.setChanged(new TraceChangeRecord<>(TraceSectionChangeType.DELETED, null, this));
	}
}
