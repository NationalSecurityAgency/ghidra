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
package ghidra.features.bsim.query.client.tables;

import java.sql.*;
import java.util.TreeMap;

public class SQLStringTable {
	public static class StringRecord {
		public long id;			// Row id of the string record
		public String value;	// The actual string
		public StringRecord prev;
		public StringRecord next;
	}

	private final String name;				// Name of the SQL table
	private final int maxLoaded;			// Maximum number of string in memory at once

	private final String insertSQL;
	private final String selectByIdSQL;
	private final String selectByValueSQL;

	private final CachedStatement<PreparedStatement> insertStatement;
	private final CachedStatement<PreparedStatement> selectByIdStatement;
	private final CachedStatement<PreparedStatement> selectByValueStatement;

	private final TreeMap<String, StringRecord> stringMap;
	private final TreeMap<Integer, StringRecord> idMap;

	private StringRecord loadedHead;		// Head of linked list
	private StringRecord loadedTail;		// End of linked list		

	private Connection db;

	public SQLStringTable(String name, int maxloaded) {
		this.name = name;
		this.maxLoaded = maxloaded;
		stringMap = new TreeMap<String, StringRecord>();
		idMap = new TreeMap<Integer, StringRecord>();

		insertSQL = generateSQLCommand("INSERT INTO # (id,val) VALUES(DEFAULT,?)");
		selectByIdSQL = generateSQLCommand("SELECT val FROM # WHERE id = ?");
		selectByValueSQL = generateSQLCommand("SELECT id FROM # WHERE val = ?");

		insertStatement = new CachedStatement<>();
		selectByIdStatement = new CachedStatement<>();
		selectByValueStatement = new CachedStatement<>();
	}

	public void setConnection(Connection db) {
		this.db = db;
	}

	public void close() {
		insertStatement.close();
		selectByIdStatement.close();
		selectByValueStatement.close();
		db = null;				// We do not own the db
		if (stringMap != null) {
			stringMap.clear();
		}
		if (idMap != null) {
			idMap.clear();
		}
		loadedHead = null;
		loadedTail = null;
	}

	/**
	 * Create this specific table in the database
	 * @throws SQLException if the create statement fails
	 */
	public void createTable() throws SQLException {
		String sqlstring =
			generateSQLCommand("CREATE TABLE # (id SERIAL PRIMARY KEY,val TEXT UNIQUE)");
		Statement st = db.createStatement();
		st.executeUpdate(sqlstring);
		st.close();
	}

	/**
	 * Try to fetch string from our memory cache, or load it from database, or return empty string
	 * 
	 * @param id the row ID
	 * @return the string fetched from the table, or empty string if not found
	 * @throws SQLException if there is a problem parsing the table record(s)
	 */
	public String getString(long id) throws SQLException {
		if (id == 0) {
			return null;
		}
		StringRecord rec = idMap.get((int) id);
		if (rec != null) {
			moveToEnd(rec);
			return rec.value;
		}
		String res = readStringRecord(id);
		if (res == null) {
			throw new SQLException("Id is not present in string table: " + name);
		}
		return res;
	}

	public long writeString(String val) throws SQLException {
		if ((val == null) || (val.length() == 0)) {
			return 0;
		}
		StringRecord rec = stringMap.get(val);
		if (rec != null) {
			moveToEnd(rec);
			return rec.id;
		}
		// String is not in cache
		long id = readStringId(val);	// Try to read from database
		if (id != 0) {
			return id;
		}
		return writeNewString(val);		// Otherwise add the string to the table
	}

	private void insertAtEnd(StringRecord rec) {
		if (loadedTail == null) {
			loadedHead = rec;
			loadedHead.prev = null;
			loadedHead.next = null;
			loadedTail = rec;
			return;
		}
		rec.prev = loadedTail;
		loadedTail.next = rec;
		rec.next = null;
		loadedTail = rec;
	}

	private StringRecord popFirst() {
		StringRecord res = loadedHead;
		loadedHead = loadedHead.next;
		if (loadedHead == null) {		// List is now empty
			loadedTail = null;
			return res;
		}
		loadedHead.prev = null;
		return res;
	}

	private void moveToEnd(StringRecord rec) {
		if (rec.next == null) {
			return;			// Already at end
		}
		StringRecord prev = rec.prev;
		rec.next.prev = prev;
		if (prev == null) {
			loadedHead = rec.next;
		}
		else {
			prev.next = rec.next;
		}
		insertAtEnd(rec);
	}

	/**
	 * Purge the top element of the -loaded- list
	 */
	private void purgeString() {
		StringRecord rec = popFirst();
		stringMap.remove(rec.value);
		idMap.remove((int) rec.id);
	}

	/**
	 * Replace '#' character in the -ptr- command with our -name- and return the string
	 * @param ptr is the string to be modified
	 * @return the modified string
	 */
	private String generateSQLCommand(String ptr) {
		int first = ptr.indexOf('#');
		int second = ptr.indexOf('#', first + 1);
		String res;
		res = ptr.substring(0, first);
		res += name;
		if (second >= 0) {
			res += ptr.substring(first + 1, second);
			res += name;
			res += ptr.substring(second + 1);
		}
		else {
			res += ptr.substring(first + 1);
		}
		return res;
	}

	private void insertRecord(long id, String value) {
		while (idMap.size() >= maxLoaded) {
			purgeString();
		}
		StringRecord rec = new StringRecord();
		insertAtEnd(rec);
		rec.id = id;
		rec.value = value;
		stringMap.put(value, rec);
		idMap.put(Integer.valueOf((int) id), rec);
	}

	private String readStringRecord(long id) throws SQLException {

		PreparedStatement s =
			selectByIdStatement.prepareIfNeeded(() -> db.prepareStatement(selectByIdSQL));
		String value = null;
		s.setInt(1, (int) id);
		try (ResultSet rs = s.executeQuery()) {
			if (!rs.next()) {
				return value;
			}
			value = rs.getString(1);
		}
		insertRecord(id, value);
		return value;
	}

	/**
	 * Try to read the id of a specific string in the table
	 * @param value is the string to try to find
	 * @return the id of the string or 0 if the string is not in the table
	 * @throws SQLException if the result set cannot be parsed
	 */
	public long readStringId(String value) throws SQLException {
		PreparedStatement s =
			selectByValueStatement.prepareIfNeeded(() -> db.prepareStatement(selectByValueSQL));
		long id = 0;
		s.setString(1, value);
		try (ResultSet rs = s.executeQuery()) {
			if (!rs.next()) {
				return id;
			}
			id = rs.getInt(1);
		}
		insertRecord(id, value);
		return id;
	}

	private long writeNewString(String value) throws SQLException {
		PreparedStatement s = insertStatement.prepareIfNeeded(
			() -> db.prepareStatement(insertSQL, Statement.RETURN_GENERATED_KEYS));
		s.setString(1, value);
		s.executeUpdate();
		try (ResultSet rs = s.getGeneratedKeys()) {
			if (!rs.next()) {
				throw new SQLException("Error during insertion");
			}
			long id = rs.getInt(1);
			insertRecord(id, value);
			return id;
		}
	}

}
