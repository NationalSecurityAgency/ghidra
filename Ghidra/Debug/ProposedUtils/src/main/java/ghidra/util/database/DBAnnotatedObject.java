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
package ghidra.util.database;

import java.io.IOException;
import java.util.List;

import db.DBRecord;
import ghidra.program.database.DatabaseObject;
import ghidra.util.LockHold;
import ghidra.util.database.DBCachedObjectStoreFactory.DBFieldCodec;

public class DBAnnotatedObject extends DatabaseObject {
	private final DBCachedObjectStore<?> store;
	private final DBCachedDomainObjectAdapter adapter;
	private final List<DBFieldCodec<?, ?, ?>> codecs;

	DBRecord record;

	@SuppressWarnings({ "unchecked", "rawtypes" })
	public DBAnnotatedObject(DBCachedObjectStore<?> store, DBRecord record) {
		super(store == null ? null : store.cache, record == null ? -1 : record.getKey());
		this.store = store;
		this.record = record;
		if (store != null) {
			this.adapter = store.adapter;
			this.codecs = (List) store.codecs;
		}
		else {
			this.adapter = null;
			this.codecs = null;
		}
	}

	/**
	 * Get an opaque unique id for this object, whose hash is immutable
	 * 
	 * @return the opaque object id
	 */
	public ObjectKey getObjectKey() {
		return new ObjectKey(store.adapter, store.table.getName(), key);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	protected void write(DBObjectColumn column) {
		DBFieldCodec codec = codecs.get(column.columnNumber);
		codec.store(this, record);
	}

	protected void update(DBObjectColumn column) {
		write(column);
		try (LockHold hold = LockHold.lock(store.writeLock())) {
			updated();
		}
		catch (IOException e) {
			store.dbError(e);
		}
	}

	protected void update(DBObjectColumn col1, DBObjectColumn col2) {
		write(col1);
		write(col2);
		try (LockHold hold = LockHold.lock(store.writeLock())) {
			updated();
		}
		catch (IOException e) {
			store.dbError(e);
		}
	}

	protected void update(DBObjectColumn col1, DBObjectColumn col2, DBObjectColumn col3) {
		write(col1);
		write(col2);
		write(col3);
		try (LockHold hold = LockHold.lock(store.writeLock())) {
			updated();
		}
		catch (IOException e) {
			store.dbError(e);
		}
	}

	protected void update(DBObjectColumn... columns) {
		for (DBObjectColumn c : columns) {
			write(c);
		}
		try (LockHold hold = LockHold.lock(store.writeLock())) {
			updated();
		}
		catch (IOException e) {
			store.dbError(e);
		}
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	protected void doUpdateAll() throws IOException {
		for (DBFieldCodec codec : codecs) {
			codec.store(this, record);
		}
		updated();
	}

	protected void updated() throws IOException {
		store.table.putRecord(record);
	}

	/**
	 * Called when the object's fields are populated.
	 * 
	 * This provides an opportunity for the object to initialize any remaining (usually
	 * non-database-backed) fields.
	 * 
	 * For a new object, the database-backed fields remain at their initial values. They will be
	 * saved after this method returns, so they may be further initialized with custom logic.
	 * 
	 * For an object loaded from the database, the database-backed fields were already populated
	 * from the record. They are <em>not</em> automatically saved after this method returns. This
	 * method should not further initialize database-backed fields in this case.
	 * 
	 * @param created {@code true} to indicate the object is being created, or {@code false} to
	 *            indicate it is being restored.
	 * @throws IOException if further initialization fails.
	 */
	protected void fresh(boolean created) throws IOException {
		// Extension point
	}

	private DBRecord getFreshRecord(DBRecord rec) throws IOException {
		if (rec != null) {
			return rec;
		}
		if (store == null) {
			return null;
		}
		if (store.table == null) {
			return null;
		}
		return store.table.getRecord(key);
	}

	@Override
	protected boolean refresh() {
		try (LockHold hold = LockHold.lock(store.readLock())) {
			return doRefresh(null);
		}
		catch (IOException e) {
			adapter.dbError(e);
			return false;
		}
	}

	@Override
	protected boolean refresh(DBRecord rec) {
		try (LockHold hold = LockHold.lock(store.readLock())) {
			return doRefresh(rec);
		}
		catch (IOException e) {
			store.dbError(e);
			return false;
		}
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	protected boolean doRefresh(DBRecord rec) throws IOException {
		rec = getFreshRecord(rec);
		if (rec == null) {
			return false;
		}
		for (DBFieldCodec c : codecs) {
			c.load(this, rec);
		}
		this.record = rec;
		fresh(false);
		return true;
	}

	public boolean isDeleted() {
		return super.isDeleted(adapter.getLock());
	}
}
