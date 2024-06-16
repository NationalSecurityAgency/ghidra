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
package ghidra.program.database;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;

import db.*;

/**
 * <code>DBStringMapAdapter</code> provides a simple string-to-string map backed by a named database table.
 * This adapter's schema must never change.
 */
public class DBStringMapAdapter {

	private final static Field[] COL_FIELDS = new Field[] { StringField.INSTANCE };
	private final static String[] COL_TYPES = new String[] { "Value" };
	private final static Schema SCHEMA =
		new Schema(0, StringField.INSTANCE, "Key", COL_FIELDS, COL_TYPES);

	private Table table;

	public DBStringMapAdapter(DBHandle dbHandle, String tableName, boolean create)
			throws IOException {
		if (create) {
			table = dbHandle.createTable(tableName, SCHEMA);
		}
		else {
			table = dbHandle.getTable(tableName);
			if (table == null) {
				throw new IOException("Table not found: " + tableName);
			}
		}
	}

	public void put(String key, String value) throws IOException {
		if (StringUtils.equals(value, get(key))) {
			return;
		}
		DBRecord record = SCHEMA.createRecord(new StringField(key));
		record.setString(0, value);
		table.putRecord(record);
	}

	public String get(String key) throws IOException {
		DBRecord record = table.getRecord(new StringField(key));
		return record != null ? record.getString(0) : null;
	}

	public int getInt(String key, int defaultValue) throws IOException {
		DBRecord record = table.getRecord(new StringField(key));
		if (record != null) {
			try {
				return Integer.valueOf(record.getString(0));
			}
			catch (NumberFormatException e) {
				// ignore parse error
			}
		}
		return defaultValue;
	}

	public boolean getBoolean(String key, boolean defaultValue) throws IOException {
		DBRecord record = table.getRecord(new StringField(key));
		if (record != null) {
			return Boolean.valueOf(record.getString(0));
		}
		return defaultValue;
	}

	public Set<String> keySet() throws IOException {
		HashSet<String> set = new HashSet<>();
		DBFieldIterator keyIter = table.fieldKeyIterator();
		while (keyIter.hasNext()) {
			set.add(keyIter.next().getString());
		}
		return set;
	}

	public void delete(String key) throws IOException {
		table.deleteRecord(new StringField(key));
	}

}
