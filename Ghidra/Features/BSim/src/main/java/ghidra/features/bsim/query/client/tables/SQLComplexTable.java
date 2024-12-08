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

import javax.help.UnsupportedOperationException;

public abstract class SQLComplexTable {

	protected final String tableName;
	protected final String idColumnName; // may be null if not applicable

	protected Connection db = null;

	private final CachedStatement<PreparedStatement> deleteStatement;

	public SQLComplexTable(String tableName, String idColumnName) {
		this.tableName = tableName;
		this.idColumnName = idColumnName;
		deleteStatement = idColumnName != null ? new CachedStatement<>() : null;
	}

	public void setConnection(Connection db) {
		this.db = db;
	}

	public void close() {
		if (deleteStatement != null) {
			deleteStatement.close();
		}
		db = null;
	}

	/**
	 * Creates the db table.
	 * 
	 * @param st the query statement
	 * @throws SQLException if there is a problem
	 */
	public abstract void create(Statement st) throws SQLException;

	/**
	 * Deletes the row with the given id from the db. Users must set the {@link #DELETE_STMT} string
	 * to delete the exact table they need.
	 * 
	 * @param id the database row ID
	 * @return the number of deleted rows
	 * @throws SQLException if there is a problem creating or executing the query
	 */
	public int delete(long id) throws SQLException {
		if (idColumnName == null) {
			throw new UnsupportedOperationException("delete not supported without id column");
		}
		PreparedStatement s = deleteStatement.prepareIfNeeded(() -> db
				.prepareStatement("DELETE FROM " + tableName + " WHERE " + idColumnName + " = ?"));
		s.setLong(1, id);
		return s.executeUpdate();
	}

	/**
	 * Drops the current table.
	 * NOTE: If explicitly created index tables exist they should be removed first
	 * or this method override.
	 * 
	 * @param st the query statement
	 * @throws SQLException if there is a problem with the execute update command
	 */
	public void drop(Statement st) throws SQLException {
		String sql = "DROP TABLE " + tableName;
		st.executeUpdate(sql);
	}

	/**
	 * Inserts a row(s) into the db. The arguments passed to this function are by definition 
	 * not known, so they are left as a variable-length list of {@link Object} instances, to be
	 * interpreted by the implementer.
	 * 
	 * @param arguments any arguments required for the insert 
	 * @return to be defined by the implementor
	 * @throws SQLException if there is a problem executing the insert command
	 */
	public abstract long insert(Object... arguments) throws SQLException;
}
