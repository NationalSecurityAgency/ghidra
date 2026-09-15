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

import db.DBRecord;
import db.Table;
import ghidra.program.database.DbCache;
import ghidra.program.database.DbFactory;

/**
 * Maps {@link DBAnnotatedObjectFactory} objects into {@link DbFactory} objects that is needed by
 * the {@link DbCache}.
 *
 * @param <T> The DBAnnotatedObject type
 */
public class DebuggerFactoryAdapter<T extends DBAnnotatedObject> implements DbFactory<T> {

	private DBCachedObjectStore<T> store;
	private Table table;
	private DBAnnotatedObjectFactory<T> factory;

	public DebuggerFactoryAdapter(DBCachedObjectStore<T> store, Table table,
			DBAnnotatedObjectFactory<T> factory) {
		this.store = store;
		this.table = table;
		this.factory = factory;
	}

	@Override
	public T instantiate(long key) {
		try {
			DBRecord record = table.getRecord(key);
			return instantiate(record);
		}
		catch (IOException e) {
			store.dbError(e);
		}
		return null;
	}

	@Override
	public T instantiate(DBRecord record) {
		if (record == null) {
			return null;
		}
		T t = factory.create(store, record);
		t.refresh(record);
		return t;
	}

}
