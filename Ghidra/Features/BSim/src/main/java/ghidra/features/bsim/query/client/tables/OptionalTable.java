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

/**
 * Database table that has exactly two columns: key and value
 * The column types are variable and are determined upon initialization.
 * They are specified by giving an integer "type code" as listed in java.sql.Types
 * The key column will be marked as UNIQUE.
 * The JDBC driver will map between Java and SQL types.
 * The readValue() writeValue() and deleteValue() methods simply take and return an Object.
 */
public class OptionalTable {

	private String TABLE_EXISTS_STMT = "SELECT schemaname FROM pg_tables where tablename='#'";
	private String GRANT_STMT = "GRANT SELECT ON # TO PUBLIC";
	private String DELETE_ALL_STMT = "DELETE FROM #";

	private String INSERT_STMT = "INSERT INTO # (key,value) VALUES(?,?)";
	private String UPDATE_STMT = "UPDATE # SET value = ? WHERE key = ?";
	private String SELECT_STMT = "SELECT value FROM # WHERE key = ?";
	private String DELETE_STMT = "DELETE FROM # WHERE key = ?";
	private String LOCK_STMT = "LOCK TABLE # IN SHARE ROW EXCLUSIVE MODE";

	private Connection db = null;			// Connection to the database

	private final CachedStatement<PreparedStatement> insertStatement = new CachedStatement<>();
	private final CachedStatement<PreparedStatement> updateStatement = new CachedStatement<>();
	private final CachedStatement<PreparedStatement> selectStatement = new CachedStatement<>();
	private final CachedStatement<PreparedStatement> deleteStatement = new CachedStatement<>();
	private final CachedStatement<Statement> reusableStatement = new CachedStatement<>();

	private String name = null;		// name of the table
	private int keyType = -1;		// Type of the key column
	private int valueType = -1;		// Type of the value column

	/**
	 * Construct this table for a specific connection
	 * @param nm is the formal SQL name of the table
	 * @param kType is the type-code of the key (as specified in java.sql.Types)
	 * @param vType is the type-code of the value (as specified in java.sql.Types)
	 * @param d is the connection to the SQL server
	 */
	public OptionalTable(String nm, int kType, int vType, Connection d) {
		name = nm;
		keyType = kType;
		valueType = vType;
		db = d;
		TABLE_EXISTS_STMT = generateSQLCommand(TABLE_EXISTS_STMT, nm);
		GRANT_STMT = generateSQLCommand(GRANT_STMT, nm);
		DELETE_ALL_STMT = generateSQLCommand(DELETE_ALL_STMT, nm);
		INSERT_STMT = generateSQLCommand(INSERT_STMT, nm);
		UPDATE_STMT = generateSQLCommand(UPDATE_STMT, nm);
		SELECT_STMT = generateSQLCommand(SELECT_STMT, nm);
		DELETE_STMT = generateSQLCommand(DELETE_STMT, nm);
		LOCK_STMT = generateSQLCommand(LOCK_STMT, nm);
	}

	private Statement getReusableStatement() throws SQLException {
		return reusableStatement.prepareIfNeeded(() -> db.createStatement());
	}

	/**
	 * Lock the table for writing
	 * @throws SQLException if the server reports an error
	 */
	public void lockForWrite() throws SQLException {
		getReusableStatement().execute(LOCK_STMT);
	}

	/**
	 * Given an sql type-code, return the sql type as a string (suitable for the CREATE TABLE command)
	 * @param type is the type-code
	 * @return the name of the type corresponding to the type-code
	 */
	private static String getSQLType(int type) {
		switch (type) {
			case Types.INTEGER:
				return "INTEGER";
			case Types.VARCHAR:
				return "TEXT";
			case Types.REAL:
				return "REAL";
		}
		return null;
	}

	/**
	 * Replace '#' character in the -ptr- command with our -name- and return the string
	 * @param ptr is the string to be modified
	 * @return the modified string
	 */
	private static String generateSQLCommand(String ptr, String name) {
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

	/**
	 * @return the formal sql name of the table
	 */
	public String getName() {
		return name;
	}

	/**
	 * @return type-code of key column
	 */
	public int getKeyType() {
		return keyType;
	}

	/**
	 * @return type-code of value column
	 */
	public int getValueType() {
		return valueType;
	}

	/**
	 * Free any resources and relinquish references to the connection
	 */
	public void close() {
		insertStatement.close();
		selectStatement.close();
		updateStatement.close();
		deleteStatement.close();
		reusableStatement.close();
		db = null;				// We do not own the db
	}

	/**
	 * Create this specific table in the database
	 * @throws SQLException for problems with the connection
	 */
	public void createTable() throws SQLException {
		StringBuilder buffer = new StringBuilder();
		buffer.append("CREATE TABLE ").append(name);
		buffer.append(" (key ").append(getSQLType(keyType)).append(" UNIQUE,value ");
		buffer.append(getSQLType(valueType)).append(')');
		String sqlstring = buffer.toString();
		Statement st = getReusableStatement();
		st.executeUpdate(sqlstring);
		st.executeUpdate(GRANT_STMT);
	}

	/**
	 * Clear all rows from the table
	 * @throws SQLException for problems with the connection
	 */
	public void clearTable() throws SQLException {
		getReusableStatement().executeUpdate(DELETE_ALL_STMT);
	}

	/**
	 * Determine whether a given table exists in the database
	 * @return true is the table exists
	 * @throws SQLException for problems with the connection
	 */
	public boolean exists() throws SQLException {
		boolean result = false;
		try (ResultSet rs = getReusableStatement().executeQuery(TABLE_EXISTS_STMT)) {
			if (rs.next()) {
				result = rs.getString(1).equals("public");
			}
		}
		return result;
	}

	/**
	 * Given a key, retrieve the corresponding value
	 * @param key identifies the table row
	 * @return the value corresponding to the key
	 * @throws SQLException for problems with the connection
	 */
	public Object readValue(Object key) throws SQLException {
		PreparedStatement s =
			selectStatement.prepareIfNeeded(() -> db.prepareStatement(SELECT_STMT));
		Object value = null;
		s.setObject(1, key, keyType);
		try (ResultSet rs = s.executeQuery()) {
			if (rs.next()) {
				value = rs.getObject(1);
			}
		}
		return value;
	}

	/**
	 * Associate a new value with a given key
	 * @param key identifies the table row
	 * @param value is stored at that row
	 * @throws SQLException for problems with the connection
	 */
	public void writeValue(Object key, Object value) throws SQLException {
		PreparedStatement s =
			updateStatement.prepareIfNeeded(() -> db.prepareStatement(UPDATE_STMT));
		s.setObject(1, value, valueType);
		s.setObject(2, key, keyType);

		if (s.executeUpdate() == 1) {
			return;		// Update was successful
		}

		s = insertStatement.prepareIfNeeded(() -> db.prepareStatement(INSERT_STMT));
		s.setObject(1, key, keyType);
		s.setObject(2, value, valueType);
		s.executeUpdate();
	}

	/**
	 * Deletes the row corresponding to a given key
	 * @param key identifies the table row
	 * @throws SQLException for problems with the connection
	 */
	public void deleteValue(Object key) throws SQLException {
		PreparedStatement s =
			deleteStatement.prepareIfNeeded(() -> db.prepareStatement(DELETE_STMT));
		s.setObject(1, key, keyType);
		s.executeUpdate();
	}
}
