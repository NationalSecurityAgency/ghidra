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
package ghidra.trace.database.data;

import java.io.IOException;
import java.util.concurrent.locks.ReadWriteLock;

import com.google.common.collect.Range;

import db.DBHandle;
import db.DBRecord;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.data.DBTraceDataSettingsAdapter.DBTraceSettingsEntry;
import ghidra.trace.database.map.*;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceDataSettingsAdapter
		extends DBTraceAddressSnapRangePropertyMap<DBTraceSettingsEntry, DBTraceSettingsEntry>
		implements DBTraceDataSettingsOperations {
	public static final String NAME = "DataSettings";

	@DBAnnotatedObjectInfo(version = 0)
	protected static class DBTraceSettingsEntry
			extends AbstractDBTraceAddressSnapRangePropertyMapData<DBTraceSettingsEntry> {
		static final String NAME_COLUMN_NAME = "Name";
		static final String LONG_VALUE_COLUMN_NAME = "LongValue";
		static final String STRING_VALUE_COLUMN_NAME = "StringValue";
		static final String BYTES_VALUE_COLUMN_NAME = "BytesValue";

		@DBAnnotatedColumn(NAME_COLUMN_NAME)
		static DBObjectColumn NAME_COLUMN;
		@DBAnnotatedColumn(LONG_VALUE_COLUMN_NAME)
		static DBObjectColumn LONG_VALUE_COLUMN;
		@DBAnnotatedColumn(STRING_VALUE_COLUMN_NAME)
		static DBObjectColumn STRING_VALUE_COLUMN;
		@DBAnnotatedColumn(BYTES_VALUE_COLUMN_NAME)
		static DBObjectColumn BYTES_VALUE_COLUMN;

		@DBAnnotatedField(column = NAME_COLUMN_NAME)
		String name;
		@DBAnnotatedField(column = LONG_VALUE_COLUMN_NAME)
		long longValue;
		@DBAnnotatedField(column = STRING_VALUE_COLUMN_NAME)
		String stringValue;
		@DBAnnotatedField(column = BYTES_VALUE_COLUMN_NAME)
		byte[] bytesValue;

		public DBTraceSettingsEntry(
				DBTraceAddressSnapRangePropertyMapTree<DBTraceSettingsEntry, ?> tree,
				DBCachedObjectStore<?> store, DBRecord record) {
			super(tree, store, record);
		}

		@Override
		protected void setRecordValue(DBTraceSettingsEntry value) {
			// Nothing. Record is value.
		}

		@Override
		protected DBTraceSettingsEntry getRecordValue() {
			return this;
		}

		void setName(String name) {
			this.name = name;
			update(NAME_COLUMN);
		}

		void setLong(long value) {
			longValue = value;
			stringValue = null;
			bytesValue = null;
			update(LONG_VALUE_COLUMN, STRING_VALUE_COLUMN, BYTES_VALUE_COLUMN);
		}

		Long getLong() {
			// Hrm. It's cheap, but it works, and it's what SettingsDB does.
			if (stringValue != null || bytesValue != null) {
				return null;
			}
			return longValue;
		}

		void setString(String value) {
			longValue = 0;
			stringValue = value;
			bytesValue = null;
			update(LONG_VALUE_COLUMN, STRING_VALUE_COLUMN, BYTES_VALUE_COLUMN);
		}

		String getString() {
			return stringValue;
		}

		void setBytes(byte[] value) {
			longValue = 0;
			stringValue = null;
			bytesValue = value;
			update(LONG_VALUE_COLUMN, STRING_VALUE_COLUMN, BYTES_VALUE_COLUMN);
		}

		byte[] getBytes() {
			return bytesValue;
		}

		void setValue(Object obj) {
			if (obj instanceof Long) {
				setLong((Long) obj);
			}
			else if (obj instanceof String) {
				setString((String) obj);
			}
			else if (obj instanceof byte[]) {
				setBytes((byte[]) obj);
			}
			else {
				throw new AssertionError(); // Other checks should trip first
			}
		}

		Object getValue() {
			if (stringValue != null) {
				return stringValue;
			}
			else if (bytesValue != null) {
				return bytesValue;
			}
			return longValue;
		}

		protected void setLifespan(Range<Long> lifespan) {
			super.doSetLifespan(lifespan);
		}
	}

	public class DBTraceDataSettingsSpace extends
			DBTraceAddressSnapRangePropertyMapSpace<DBTraceSettingsEntry, DBTraceSettingsEntry>
			implements DBTraceDataSettingsOperations {
		public DBTraceDataSettingsSpace(String tableName, DBCachedObjectStoreFactory storeFactory,
				ReadWriteLock lock, AddressSpace space, Class<DBTraceSettingsEntry> dataType,
				DBTraceAddressSnapRangePropertyMapDataFactory<DBTraceSettingsEntry, DBTraceSettingsEntry> dataFactory)
				throws VersionException, IOException {
			super(tableName, storeFactory, lock, space, dataType, dataFactory);
		}

		@Override
		public void makeWay(DBTraceSettingsEntry entry, Range<Long> span) {
			DBTraceUtils.makeWay(entry, span, (e, s) -> e.setLifespan(s), e -> deleteData(e));
		}

		@Override
		public ReadWriteLock getLock() {
			return lock;
		}
	}

	public class DBTraceDataSettingsRegisterSpace extends
			DBTraceAddressSnapRangePropertyMapRegisterSpace<DBTraceSettingsEntry, DBTraceSettingsEntry>
			implements DBTraceDataSettingsOperations {
		public DBTraceDataSettingsRegisterSpace(String tableName,
				DBCachedObjectStoreFactory storeFactory, ReadWriteLock lock, AddressSpace space,
				DBTraceThread thread, int frameLevel, Class<DBTraceSettingsEntry> dataType,
				DBTraceAddressSnapRangePropertyMapDataFactory<DBTraceSettingsEntry, DBTraceSettingsEntry> dataFactory)
				throws VersionException, IOException {
			super(tableName, storeFactory, lock, space, thread, frameLevel, dataType, dataFactory);
		}

		@Override
		public void makeWay(DBTraceSettingsEntry entry, Range<Long> span) {
			DBTraceUtils.makeWay(entry, span, (e, s) -> e.setLifespan(s), e -> deleteData(e));
		}

		@Override
		public ReadWriteLock getLock() {
			return lock;
		}
	}

	public DBTraceDataSettingsAdapter(DBHandle dbh, DBOpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, Language baseLanguage, DBTrace trace,
			DBTraceThreadManager threadManager) throws IOException, VersionException {
		super(NAME, dbh, openMode, lock, monitor, baseLanguage, trace, threadManager,
			DBTraceSettingsEntry.class, DBTraceSettingsEntry::new);
	}

	@Override
	protected DBTraceAddressSnapRangePropertyMapSpace<DBTraceSettingsEntry, DBTraceSettingsEntry> createSpace(
			AddressSpace space, DBTraceSpaceEntry ent) throws VersionException, IOException {
		return new DBTraceDataSettingsSpace(
			tableName(space, ent.getThreadKey(), ent.getFrameLevel()),
			trace.getStoreFactory(), lock, space, dataType, dataFactory);
	}

	@Override
	protected DBTraceAddressSnapRangePropertyMapRegisterSpace<DBTraceSettingsEntry, DBTraceSettingsEntry> createRegisterSpace(
			AddressSpace space, DBTraceThread thread, DBTraceSpaceEntry ent)
			throws VersionException, IOException {
		return new DBTraceDataSettingsRegisterSpace(
			tableName(space, ent.getThreadKey(), ent.getFrameLevel()),
			trace.getStoreFactory(), lock, space, thread, ent.getFrameLevel(), dataType,
			dataFactory);
	}

	@Override
	public DBTraceDataSettingsSpace get(TraceAddressSpace space, boolean createIfAbsent) {
		return (DBTraceDataSettingsSpace) super.get(space, createIfAbsent);
	}

	@Override
	public DBTraceDataSettingsSpace getForSpace(AddressSpace space, boolean createIfAbsent) {
		return (DBTraceDataSettingsSpace) super.getForSpace(space, createIfAbsent);
	}

	@Override
	public DBTraceDataSettingsRegisterSpace getRegisterSpace(TraceThread thread,
			boolean createIfAbsent) {
		return (DBTraceDataSettingsRegisterSpace) super.getRegisterSpace(thread, createIfAbsent);
	}

	@Override
	public void makeWay(DBTraceSettingsEntry entry, Range<Long> span) {
		DBTraceUtils.makeWay(entry, span, (e, s) -> e.setLifespan(s), e -> deleteData(e));
	}
}
