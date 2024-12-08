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
import java.util.ArrayList;
import java.util.List;

import javax.help.UnsupportedOperationException;

import ghidra.features.bsim.query.description.*;

public class CallgraphTable extends SQLComplexTable {

	private static final String SELECT_STMT = "SELECT ALL * FROM callgraphtable WHERE src = ?";
	private static final String INSERT_STMT = "INSERT INTO callgraphtable (src,dest) VALUES(?,?)";

	public static class CallgraphRow {
		public long src;
		public long dest;
	}

	private final CachedStatement<PreparedStatement> selectStatement = new CachedStatement<>();
	private final CachedStatement<PreparedStatement> insertStatement = new CachedStatement<>();

	public CallgraphTable() {
		super("callgraphtable", "src");
	}

	@Override
	public void close() {
		selectStatement.close();
		insertStatement.close();
		super.close();
	}

	@Override
	public void create(Statement st) throws SQLException {
		st.executeUpdate(
			"CREATE TABLE callgraphtable (src BIGINT,dest BIGINT,PRIMARY KEY (src,dest) )");
	}

	@Override
	public void drop(Statement st) throws SQLException {
		throw new UnsupportedOperationException("CallgraphTable may not be dropped");
	}

	/**
	 * 
	 * @param pgres the result set to extract from
	 * @return the new {@link CallgraphRow}
	 * @throws SQLException if there's an error parsing the {@link ResultSet}
	 */
	public static CallgraphRow extractCallgraphRow(ResultSet pgres) throws SQLException {
		CallgraphRow res = new CallgraphRow();
		res.src = pgres.getLong(1);
		res.dest = pgres.getLong(2);
		return res;
	}

	/**
	 * 
	 * @param func the function description
	 * @param trackcallgraph true if the database tracks call graph information
	 * @return the list of {@link CallgraphRow}s
	 * @throws SQLException if there is a problem parsing the {@link ResultSet} objects
	 */
	public List<CallgraphRow> queryCallgraphRows(FunctionDescription func,
		boolean trackcallgraph) throws SQLException {
		if (!trackcallgraph) {
			throw new SQLException("SQL database does not have callgraph information enabled");
		}
		PreparedStatement s =
			selectStatement.prepareIfNeeded(() -> db.prepareStatement(SELECT_STMT));
		RowKey funcid = func.getId();
		if (funcid == null) {
			throw new SQLException("FunctionDescription does not have id");
		}
		s.setLong(1, funcid.getLong());
		try (ResultSet rs = s.executeQuery()) {
			List<CallgraphRow> callvec = new ArrayList<>();
			while (rs.next()) {
				CallgraphRow row = extractCallgraphRow(rs);
				if (row.dest == 0) {
					continue;
				}
				callvec.add(row);
			}
			return callvec;
		}
	}

	@Override
	public long insert(Object... arguments) throws SQLException {

		if (arguments == null || arguments.length != 1 ||
			!(arguments[0] instanceof FunctionDescription)) {
			throw new IllegalArgumentException(
				"Insert method for CallgraphTable must take exactly one FunctionDescription argument");
		}

		FunctionDescription func = (FunctionDescription) arguments[0];

		PreparedStatement s =
			insertStatement.prepareIfNeeded(() -> db.prepareStatement(INSERT_STMT));
		long srcid = func.getId().getLong();
		List<CallgraphEntry> callvec = func.getCallgraphRecord();
		if (callvec != null) {
			for (CallgraphEntry element : callvec) {
				FunctionDescription destFunc = element.getFunctionDescription();
				long destid = destFunc.getId().getLong();
				s.setLong(1, srcid);
				s.setLong(2, destid);
				s.executeUpdate();
			}
		}

		return 0;
	}
}
