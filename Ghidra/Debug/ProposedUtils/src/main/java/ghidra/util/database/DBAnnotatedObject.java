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
import ghidra.util.database.annot.DBAnnotatedObjectInfo;

/**
 * An object backed by a {@link DBRecord}
 * 
 * <p>
 * Essentially, this is a data access object (DAO) for Ghidra's custom database engine. Not all
 * object fields necessarily have a corresponding database field. Instead, those fields are
 * annotated, and various methods are provided for updating the record, and conversely, re-loading
 * fields from the record. These objects are managed using a {@link DBCachedObjectStore}. An example
 * object definition:
 * 
 * <pre>
 * interface Person {
 * 	// ...
 * }
 * 
 * &#64;DBAnnotatedObjectInfo(version = 1)
 * public class DBPerson extends DBAnnotatedObject implements Person {
 * 	public static final String TABLE_NAME = "Person"; // Conventionally defined here
 * 
 * 	// Best practice is to define column names, then use in annotations
 * 	static final String NAME_COLUMN_NAME = "Name";
 * 	static final String ADDRESS_COLUMN_NAME = "Address";
 * 
 * 	// Column handles
 * 	&#64;DBAnnotatedColumn(NAME_COLUMN_NAME)
 * 	static DBObjectColumn NAME_COLUMN;
 * 	&#64;DBAnnotatedColumn(ADDRESS_COLUMN_NAME)
 * 	static DBObjectColumn ADDRESS_COLUMN;
 * 
 * 	// Column-backed fields
 * 	&#64;DBAnnotatedField(column = NAME_COLUMN_NAME, indexed = true)
 * 	private String name;
 * 	&#64;DBAnnotatedField(column = ADDRESS_COLUMN_NAME)
 * 	private String address;
 * 
 * 	DBPerson(DBCachedObjectStore<DBPerson> store, DBRecord record) {
 * 		super(store, record);
 * 	}
 * 
 * 	// Not required, but best practice
 * 	private void set(String name, String address) {
 * 		this.name = name;
 * 		this.address = address;
 * 		update(NAME_COLUMN, ADDRESS_COLUMN);
 * 	}
 * 
 * 	// ... other methods, getters, setters
 * }
 * </pre>
 * 
 * <p>
 * See {@link DBCachedObjectStoreFactory} for example code that uses the example {@code DBPerson}
 * class.
 * 
 * <p>
 * All realizations of {@link DBAnnotatedObject} must be annotated with
 * {@link DBAnnotatedObjectInfo}. This, along with the field annotations, are used to derive the
 * table schema. Note the inclusion of a {@code TABLE_NAME} field. It is not required, nor is it
 * used implicitly. It's included in this example as a manner of demonstrating best practice. When
 * instantiating the object store, the field is used to provide the table name.
 * <p>
 * Next, we define the column names. These are not required nor used implicitly, but using literal
 * strings in the column annotations is discouraged. Next, we declare variables to receive column
 * handles. These are essentially the column numbers, but we have a named handle for each. They are
 * initialized automatically the first time a store is created for this class.
 * <p>
 * Next we declare the variables representing the actual column values. Their initialization varies
 * depending on how the object is instantiated. When creating a new object, the fields remain
 * uninitialized. In some cases, it may be appropriate to provide an initial (default) value in the
 * usual fashion, e.g., {@code private String address = "123 Pine St.";} In this case, the
 * corresponding database field of the backing record is implicitly initialized upon creation. If
 * the object is being loaded from a table, its fields are initialized with values from its backing
 * record.
 *
 * <p>
 * Next we define the constructor. There are no requirements on its signature, but it must call
 * {@link #DBAnnotatedObject(DBCachedObjectStore, DBRecord) super}, so it likely takes its
 * containing store and its backing record. Having the same signature as its super constructor
 * allows the store to be created using a simple method reference, e.g., {@code DBPerson::new}.
 * Additional user-defined parameters may be accepted. To pass such parameters, a lambda is
 * recommended when creating the object store.
 * <p>
 * Finally, we demonstrate how to update the record. The record is <em>not</em> implicitly updated
 * by direct modification of an annotated field. All setters must call
 * {@link #update(DBObjectColumn...)} after updating a field. A common practice, especially when the
 * object will have all its fields set at once, is to include a {@code set} method that initializes
 * the fields and updates the record in one {@link #update(DBObjectColumn...)}.
 * 
 * <p>
 * Note that there is no way to specify the primary key. For object stores, the primary key is
 * always the object id, and its type is always {@code long}.
 */
public class DBAnnotatedObject extends DatabaseObject {
	private final DBCachedObjectStore<?> store;
	private final DBCachedDomainObjectAdapter adapter;
	private final List<DBFieldCodec<?, ?, ?>> codecs; // The codecs, ordered by field

	DBRecord record; // The backing record

	/**
	 * The object constructor
	 * 
	 * @param store the store containing this object
	 * @param record the record backing this object
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	protected DBAnnotatedObject(DBCachedObjectStore<?> store, DBRecord record) {
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
		return new ObjectKey(store.table, key);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	protected void doWrite(DBObjectColumn column) {
		DBFieldCodec codec = codecs.get(column.columnNumber);
		codec.store(this, record);
	}

	/**
	 * 1-arity version of {@link #update(DBObjectColumn...)}
	 * 
	 * @param column the column
	 */
	protected void update(DBObjectColumn column) {
		doWrite(column);
		try (LockHold hold = LockHold.lock(store.writeLock())) {
			doUpdated();
		}
		catch (IOException e) {
			store.dbError(e);
		}
	}

	/**
	 * 2-arity version of {@link #update(DBObjectColumn...)}
	 * 
	 * @param col1 a column
	 * @param col2 another column
	 */
	protected void update(DBObjectColumn col1, DBObjectColumn col2) {
		doWrite(col1);
		doWrite(col2);
		try (LockHold hold = LockHold.lock(store.writeLock())) {
			doUpdated();
		}
		catch (IOException e) {
			store.dbError(e);
		}
	}

	/**
	 * 2-arity version of {@link #update(DBObjectColumn...)}
	 * 
	 * @param col1 a column
	 * @param col2 another column
	 * @param col3 another column
	 */
	protected void update(DBObjectColumn col1, DBObjectColumn col2, DBObjectColumn col3) {
		doWrite(col1);
		doWrite(col2);
		doWrite(col3);
		try (LockHold hold = LockHold.lock(store.writeLock())) {
			doUpdated();
		}
		catch (IOException e) {
			store.dbError(e);
		}
	}

	/**
	 * Write the given columns into the record and update the table
	 * 
	 * @param columns the columns to update
	 */
	protected void update(DBObjectColumn... columns) {
		for (DBObjectColumn c : columns) {
			doWrite(c);
		}
		try (LockHold hold = LockHold.lock(store.writeLock())) {
			doUpdated();
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
		doUpdated();
	}

	protected void doUpdated() throws IOException {
		store.table.putRecord(record);
	}

	/**
	 * Extension point: Called when the object's fields are populated.
	 * 
	 * <p>
	 * This provides an opportunity for the object to initialize any non-database-backed fields that
	 * depend on the database-backed fields. Note that its use may indicate a situation better
	 * solved by a custom {@link DBFieldCodec}. If both the database-backed and non-database-backed
	 * fields are used frequently, then a codec may not be indicated. If the database-backed fields
	 * are only used in this method or to encode another frequently-used field, then a codec is
	 * likely better.
	 * 
	 * <p>
	 * For a new object, the database-backed fields remain at their initial values. They will be
	 * saved after this method returns, so they may be further initialized with custom logic.
	 * 
	 * <p>
	 * For an object loaded from the database, the database-backed fields are already populated from
	 * the record when this method is called. They are <em>not</em> automatically saved after this
	 * method returns. This method should not further initialize database-backed fields in this
	 * case.
	 * 
	 * @param created {@code true} when object is being created, or {@code false} when it is being
	 *            loaded.
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

	/**
	 * Check if this object has been deleted
	 * 
	 * @see #isDeleted(ghidra.util.Lock)
	 * @return true if deleted
	 */
	public boolean isDeleted() {
		return super.isDeleted(adapter.getLock());
	}
}
