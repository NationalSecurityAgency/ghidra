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

import ghidra.features.bsim.query.description.DatabaseInformation;

public class KeyValueTable extends SQLComplexTable {

	private final String INSERT_STMT = "INSERT INTO keyvaluetable (key,value) VALUES(?,?)";
	private final String UPDATE_STMT = "UPDATE keyvaluetable SET value = ? WHERE key = ?";
	private final String SELECT_STMT = "SELECT value FROM keyvaluetable WHERE key = ?";

	private final CachedStatement<PreparedStatement> insertStatement = new CachedStatement<>();
	private final CachedStatement<PreparedStatement> updateStatement = new CachedStatement<>();
	private final CachedStatement<PreparedStatement> selectStatement = new CachedStatement<>();

	public KeyValueTable() {
		super("keyvaluetable", null);
	}

	@Override
	public void close() {
		insertStatement.close();
		updateStatement.close();
		selectStatement.close();
		super.close();
	}

	@Override
	public void create(Statement st) throws SQLException {
		st.executeUpdate("CREATE TABLE keyvaluetable (key TEXT UNIQUE,value TEXT)");
	}

	@Override
	public void drop(Statement st) throws SQLException {
		throw new UnsupportedOperationException("KeyValueTable may not be dropped");
	}

	@Override
	public long insert(Object... arguments) throws SQLException {

		if (arguments == null || arguments.length != 2 || !(arguments[0] instanceof String) ||
			!(arguments[1] instanceof String)) {
			throw new IllegalArgumentException(
				"Insert method for KeyValueTable must take exactly two arguments: String and String");
		}

		String key = (String) arguments[0];
		String value = (String) arguments[1];

		PreparedStatement s =
			updateStatement.prepareIfNeeded(() -> db.prepareStatement(UPDATE_STMT));
		s.setString(2, key);
		s.setString(1, value);

		if (s.executeUpdate() == 1) {
			return 0; // Update was successful
		}

		s = insertStatement.prepareIfNeeded(() -> db.prepareStatement(INSERT_STMT));
		s.setString(1, key);
		s.setString(2, value);
		s.executeUpdate();

		return 0;
	}

	/**
	 * Inserts some properties from the {@link DatabaseInformation} object to the table.
	 * 
	 * @param info the database information
	 * @throws SQLException if the database info cannot be stored in the table
	 */
	public void writeBasicInfo(DatabaseInformation info) throws SQLException {
		insert("name", info.databasename);
		insert("owner", info.owner);
		insert("description", info.description);
		insert("major", Integer.toString(info.major));
		insert("minor", Integer.toString(info.minor));
		insert("settings", Integer.toString(info.settings));
		insert("layout", Integer.toString(info.layout_version));
		String tf = info.readonly ? "t" : "f";
		insert("readonly", tf);
		tf = info.trackcallgraph ? "t" : "f";
		insert("trackcallgraph", tf);
		String datename = info.dateColumnName;
		if (datename == null) {
			datename = "Ingest Date";
		}
		insert("datecolumn", datename);
		writeExecutableCategories(info);
		writeFunctionTags(info);
	}

	/**
	 * 
	 * @param info the database information
	 * @throws SQLException if the table insert fails
	 */
	public void writeExecutableCategories(DatabaseInformation info) throws SQLException {
		if (info.execats == null) {
			insert("execatcount", "0");
			return;
		}
		insert("execatcount", Integer.toString(info.execats.size()));
		for (int i = 0; i < info.execats.size(); ++i) {
			String key = "execat" + Integer.toString(i + 1);
			insert(key, info.execats.get(i));
		}
	}

	/**
	 * @param info the database information
	 * @throws SQLException if the table insert fails
	 */
	public void writeFunctionTags(DatabaseInformation info) throws SQLException {
		if (info.functionTags == null) {
			insert("functiontagcount", "0");
			return;
		}
		insert("functiontagcount", Integer.toString(info.functionTags.size()));
		for (int i = 0; i < info.functionTags.size(); ++i) {
			String key = "functiontag" + Integer.toString(i + 1);
			insert(key, info.functionTags.get(i));
		}
	}

	/**
	 * 
	 * @param key the key to get the value for
	 * @return the value associated with key or throw exception if key not present
	 * @throws SQLException if the sql statement cannot be parsed
	 */
	public String getValue(String key) throws SQLException {
		PreparedStatement s =
			selectStatement.prepareIfNeeded(() -> db.prepareStatement(SELECT_STMT));
		s.setString(1, key);
		try (ResultSet rs = s.executeQuery()) {
			String value;
			if (rs.next()) {
				value = rs.getString(1);
			}
			else {
				throw new SQLException("Could not fetch key value: " + key);
			}
			return value;
		}
	}

}
