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

import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.client.RowKeySQL;
import ghidra.features.bsim.query.client.tables.ExeTable.ExecutableRow;
import ghidra.features.bsim.query.description.*;

/**
 * This is the SQL table "desctable", which holds one row for each function ingested into the database.
 * A row (DescriptionRow) consists of basic meta-data about the function: name, spaceid, address, executable
 */
public class DescriptionTable extends SQLComplexTable {

	//@formatter:off
	private static final String INSERT_STMT =
		"INSERT INTO desctable (id,name_func,id_exe,id_signature,flags,spaceid,addr) VALUES(DEFAULT,?,?,?,?,?,?)";
	private static final String SELECT_BY_SIGNATURE_ID_STMT =
		"SELECT ALL * FROM  desctable WHERE id_signature = "; // used as simple Statement w/ appended param
	private static final String SELECT_BY_FUNC_NAMEADDR_STMT =
		"SELECT ALL * FROM  desctable WHERE name_func = ? AND spaceid = ? AND addr = ? AND id_exe = ?";
	private static final String SELECT_BY_FUNC_NAME_STMT =
		"SELECT ALL * FROM  desctable WHERE name_func = ? AND id_exe = ?";
	//@formatter:on

	public static class DescriptionRow {
		public long rowid;				// Row id of the function within -desctable-
		public String func_name;		// Name of the function
		public long id_exe;				// Row id of the executable (within exetable) containing function
		public long id_sig;				// Row id of the feature vector (within vectortable) describing function
		public int spaceid;				// The Address Space ID of the function
		public long addr;				// The (starting) address of the function
		public int flags;				// bit vector describing tags that are active for this function
	}

	private String selectWithFilterTableClause = null;
	private String selectWithFilterWhereClause = null;
	private final CachedStatement<PreparedStatement> selectWithFilterStatement =
		new CachedStatement<>();

	private final CachedStatement<PreparedStatement> selectByFuncAddrAndExeStatement =
		new CachedStatement<>();
	private final CachedStatement<PreparedStatement> selectByFuncAndExeStatement =
		new CachedStatement<>();
	private final CachedStatement<PreparedStatement> insertStatement = new CachedStatement<>();
	private final CachedStatement<PreparedStatement> selectByRowIdStatement =
		new CachedStatement<>();

	private ExeTable exeTable = null;

	public DescriptionTable(ExeTable exeTable) {
		super("desctable", "id_exe");
		this.exeTable = exeTable;
	}

	@Override
	public void close() {
		selectWithFilterStatement.close();
		selectByFuncAddrAndExeStatement.close();
		selectByFuncAndExeStatement.close();
		insertStatement.close();
		selectByRowIdStatement.close();
		super.close();
	}

	@Override
	public void create(Statement st) throws SQLException {
		st.executeUpdate("CREATE TABLE  desctable" +
			" (id BIGSERIAL PRIMARY KEY,name_func TEXT,id_exe INTEGER,id_signature BIGINT,flags INTEGER,spaceid INTEGER,addr BIGINT)");
		st.executeUpdate("CREATE INDEX sigindex ON desctable (id_signature)");
		st.executeUpdate("CREATE INDEX exefuncindex ON desctable (id_exe,name_func,spaceid,addr)");
	}

	@Override
	public void drop(Statement st) throws SQLException {
		throw new UnsupportedOperationException("DescriptionTable may not be dropped");
	}

	/**
	 * Given the row id of the function within desctable, extract the FunctionDescription object
	 * @param descManager is the container which will hold the object
	 * @param rowId is the row id of the function within desctable
	 * @return the FunctionDescription
	 * @throws SQLException if there is a problem creating or executing the query
	 * @throws LSHException if there is a problem parsing the result set
	 */
	public FunctionDescription querySingleDescriptionId(DescriptionManager descManager, long rowId)
		throws SQLException, LSHException {
		PreparedStatement s = selectByRowIdStatement.prepareIfNeeded(
			() -> db.prepareStatement("SELECT ALL * FROM desctable WHERE id = ?"));
		s.setLong(1, rowId);
		try (ResultSet rs = s.executeQuery()) {
			FunctionDescription fres;
			fres = extractSingleDescriptionRow(rs, descManager);
			if (fres == null) {
				throw new SQLException("No desctable rows matching id");
			}
			return fres;
		}
	}

	/**
	 * Process a result set (expected to contain a single row) from desctable,
	 * building the FunctionDescription object described by the row
	 * @param resultSet is the result set
	 * @param descManager is the container that will hold the resulting FunctionDescription
	 * @return the new FunctionDescription
	 * @throws SQLException if there is a problem creating or executing the query
	 * @throws LSHException if there is a problem creating the executable record
	 */
	private FunctionDescription extractSingleDescriptionRow(ResultSet resultSet,
		DescriptionManager descManager) throws SQLException, LSHException {
		boolean finished = false;
		DescriptionRow currow = null;

		while (resultSet.next()) {
			if (!finished) {
				currow = new DescriptionRow();
				extractDescriptionRow(resultSet, currow);
				finished = true;
			}
		}
		if (currow == null) {
			return null;
		}

		RowKey rowKey = new RowKeySQL(currow.id_exe);
		ExecutableRecord curexe = descManager.findExecutableByRow(rowKey);
		if (curexe == null) {
			ExecutableRow exerow = exeTable.querySingleExecutableId(currow.id_exe);
			curexe = exeTable.makeExecutableRecord(descManager, exerow);
			descManager.cacheExecutableByRow(curexe, rowKey);
		}

		return convertDescriptionRow(currow, curexe, descManager, null);
	}

	/**
	 * Given rows from desctable describing functions of a single executable,
	 * build the list of corresponding FunctionDescription objects
	 * @param descList is resulting list of FunctionDescriptions
	 * @param rowList is the list of DescriptionRows
	 * @param executable is the ExecutableRecord of the single executable
	 * @param descManager is the container to hold the new FunctionDescriptions
	 * @param sigRecord is a single SignatureRecord to associate with any new
	 *            FunctionDescription (can be null)
	 */
	public void convertDescriptionRows(List<FunctionDescription> descList,
		List<DescriptionRow> rowList, ExecutableRecord executable,
		DescriptionManager descManager, SignatureRecord sigRecord) {
		if (rowList.isEmpty()) {
			return;
		}
		DescriptionRow currow = rowList.get(0);

		FunctionDescription fres =
			convertDescriptionRow(currow, executable, descManager, sigRecord);
		descList.add(fres);
		if (sigRecord != null) {
			descManager.setSignatureId(sigRecord, currow.id_sig);
		}
		for (int i = 1; i < rowList.size(); ++i) {
			currow = rowList.get(i);
			fres = convertDescriptionRow(currow, executable, descManager, sigRecord);
			descList.add(fres);
		}
	}

	/**
	 * Given a function's raw meta-data from a desctable row (DescriptionRow), build the
	 * corresponding high-level FunctionDescription
	 * @param descRow is the function's row meta-data
	 * @param exeRecord is the ExecutableRecord for executable containing the function
	 * @param descManager is the container that will hold the new FunctionDescription
	 * @param sigRecord is SignatureRecord associated with the function (may be null)
	 * @return the new FunctionDescription
	 */
	public static FunctionDescription convertDescriptionRow(DescriptionRow descRow,
		ExecutableRecord exeRecord, DescriptionManager descManager, SignatureRecord sigRecord) {
		FunctionDescription fres =
			descManager.newFunctionDescription(descRow.func_name, descRow.spaceid, descRow.addr, exeRecord);
		descManager.setFunctionDescriptionId(fres, new RowKeySQL(descRow.rowid));
		descManager.setFunctionDescriptionFlags(fres, descRow.flags);
		descManager.setSignatureId(fres, descRow.id_sig);
		if (sigRecord != null) {
			descManager.attachSignature(fres, sigRecord);
		}
		return fres;
	}

	/**
	 * Extract column meta-data of a desctable row from the SQL result set
	 * @param resultSet is the low-level result set (returned by an SQL query)
	 * @param descRow is the DescriptionRow 
	 * @throws SQLException if there is a problem parsing the result set
	 */
	public static void extractDescriptionRow(ResultSet resultSet, DescriptionRow descRow)
		throws SQLException {
		descRow.rowid = resultSet.getLong(1);
		descRow.func_name = resultSet.getString(2);
		descRow.id_exe = resultSet.getInt(3);
		descRow.id_sig = resultSet.getLong(4);
		descRow.flags = resultSet.getInt(5);
		descRow.spaceid = resultSet.getInt(6);
		descRow.addr = resultSet.getLong(7);

	}

	/**
	 * Extract a list of desctable rows from the SQL result set
	 * Only build up to -max- DescriptionRow objects, but still run through all rows in the set.
	 * @param resultSet is the ResultSet to run through
	 * @param maxRows is the maximum number of DescriptionRows to build
	 * @return a list of the new DescriptionRows
	 * @throws SQLException if there is a problem parsing the result set
	 */
	public List<DescriptionRow> extractDescriptionRows(ResultSet resultSet, int maxRows)
		throws SQLException {
		List<DescriptionRow> descvec = new ArrayList<>();
		boolean finished = false;

		while (resultSet.next()) {
			if (!finished) {
				DescriptionRow row = new DescriptionRow();
				descvec.add(row);
				extractDescriptionRow(resultSet, row);
				if ((maxRows > 0) && (descvec.size() >= maxRows)) {
					// maximum number of
					// rows
					finished = true;
				}
			}
		}
		return descvec;
	}

	/**
	 * Assuming all the necessary ids have been filled in, store the function as a row in desctable
	 * 
	 * @param arguments must be a single {@link FunctionDescription}
	 * @throws SQLException if there is a problem creating or executing the query
	 */
	@Override
	public long insert(Object... arguments) throws SQLException {

		if (arguments == null || arguments.length != 1 ||
			!(arguments[0] instanceof FunctionDescription)) {
			throw new IllegalArgumentException(
				"Insert method for KeyValueTable must take exactly one FunctionDescription argument");
		}

		FunctionDescription func = (FunctionDescription) arguments[0];
		SignatureRecord srec = func.getSignatureRecord();
		long vecid = 0;
		if (srec != null) {
			vecid = srec.getVectorId();
		}

		PreparedStatement s = insertStatement.prepareIfNeeded(
			() -> db.prepareStatement(INSERT_STMT, Statement.RETURN_GENERATED_KEYS));
		s.setString(1, func.getFunctionName());
		s.setInt(2, (int) func.getExecutableRecord().getRowId().getLong());
		s.setLong(3, vecid);
		s.setInt(4, func.getFlags());
		s.setInt(5, func.getSpaceID());
		s.setLong(6, func.getAddress());
		s.executeUpdate();

		try (ResultSet rs = s.getGeneratedKeys()) {
			if (!rs.next()) {
				throw new SQLException("Did not get desctable sequence number after insertion");
			}
			return rs.getLong(1);
		}
	}

	/**
	 * Return function DescriptionRow objects that have a matching vector id
	 * 
	 * @param vectorId is the row id of the feature vector we want to match
	 * @param maxRows is the maximum number of function rows to return
	 * @return list of resulting DescriptionRows
	 * @throws SQLException if there is a problem creating or executing the query
	 */
	public List<DescriptionRow> queryVectorIdMatch(long vectorId, int maxRows)
		throws SQLException {

		StringBuffer buf = new StringBuffer();
		buf.append(SELECT_BY_SIGNATURE_ID_STMT).append(vectorId);
		if (maxRows > 0) {
			buf.append(" LIMIT ").append(maxRows);
		}

		try (Statement select_desctable_id_signature_stmt = db.createStatement();
			ResultSet rs = select_desctable_id_signature_stmt.executeQuery(buf.toString())) {
			select_desctable_id_signature_stmt.setFetchSize(50);
			List<DescriptionRow> descres = null;
			descres = extractDescriptionRows(rs, maxRows);
			return descres;
		}
	}

	/**
	 * Return function DescriptionRow objects that have a matching vector id
	 * and that also pass additional filters.  The filters must be encoded
	 * as a "WHERE" clause of an SQL "SELECT" statement on desctable. Additional
	 * tables joined to desctable to satisfy the filter must be encoded as
	 * a "FROM" clause of the "SELECT".
	 * @param vectorId is the row id of the feature vector (vectortable) we want to match on
	 * @param tableClause is the additional "FROM" clause needed for the filter
	 * @param whereClause is the "WHERE" clause needed for the filter
	 * @param maxRows is the maximum number of rows to return
	 * @return a list of resulting DescriptionRows
	 * @throws SQLException if there is an error creating or executing the query
	 */
	public List<DescriptionRow> queryVectorIdMatchFilter(long vectorId, String tableClause,
		String whereClause, int maxRows) throws SQLException {

		PreparedStatement s = selectWithFilterStatement.getStatement();
		if (s == null || !tableClause.equals(selectWithFilterTableClause) ||
			!whereClause.equals(selectWithFilterWhereClause)) {
			selectWithFilterStatement.close();
			selectWithFilterTableClause = tableClause;
			selectWithFilterWhereClause = whereClause;
			StringBuffer buf = new StringBuffer();
			buf.append(
				"SELECT desctable.id,desctable.name_func,desctable.id_exe,desctable.id_signature,desctable.flags,desctable.spaceid,desctable.addr FROM desctable");
			buf.append(tableClause);
			buf.append(" WHERE desctable.id_signature = ? ");
			buf.append(whereClause);
			buf.append(" LIMIT ?");
			s = db.prepareStatement(buf.toString());
			selectWithFilterStatement.setStatement(s);
		}

		if (maxRows == 0) {
			maxRows = 1000000;
		}
		s.setLong(1, vectorId);
		s.setInt(2, maxRows);
		s.setFetchSize(50);
		try (ResultSet rs = s.executeQuery()) {
			return extractDescriptionRows(rs, maxRows);
		}
	}

	/**
	 * Return DescriptionRow objects that match a given -functionName-
	 * and the row id within exetable of a specific executable
	 * @param executableId is the row id of the executable to match
	 * @param functionName is the name of the function to match
	 * @param maxRows is the maximum number of functions to return
	 * @return linked of DescriptionRow objects
	 * @throws SQLException if there is an error creating or executing the query
	 */
	public List<DescriptionRow> queryFuncName(long executableId, String functionName,
		int maxRows) throws SQLException {
		PreparedStatement s = selectByFuncAndExeStatement
			.prepareIfNeeded(() -> db.prepareStatement(SELECT_BY_FUNC_NAME_STMT));
		s.setString(1, functionName);
		s.setInt(2, (int) executableId);
		s.setFetchSize(50);
		try (ResultSet rs = s.executeQuery()) {
			return extractDescriptionRows(rs, maxRows);
		}
	}

	/**
	 * Query the description table for the row describing a single function.
	 * A function is uniquely identified by: its name, its address (address space + offset), and the executable it is in
	 * @param executableId is the row id (of exetable) of the executable containing the function
	 * @param functionName is the name of the function
	 * @param spaceID is the address space ID of the function address
	 * @param functionAddress is the address offset of the function
	 * @return the corresponding row of the table, or null
	 * @throws SQLException if there is an error creating or executing the query
	 */
	public DescriptionRow queryFuncNameAddr(long executableId, String functionName,
		int spaceID, long functionAddress) throws SQLException {
		PreparedStatement s = selectByFuncAddrAndExeStatement
			.prepareIfNeeded(() -> db.prepareStatement(SELECT_BY_FUNC_NAMEADDR_STMT));
		s.setString(1, functionName);
		s.setInt(2, spaceID);
		s.setLong(3, functionAddress);
		s.setInt(4, (int) executableId);
		s.setFetchSize(4);	// Should only every be at most 1

		DescriptionRow resultRow = null;
		try (ResultSet rs = s.executeQuery()) {
			boolean finished = false;
			// TODO: Should be no need to get every row
			while (rs.next()) {		// To ensure JDBC resources are cleaned up make sure to visit every element
				if (!finished) {	//  of the result set even if we don't build a DescriptionRow for every element
					resultRow = new DescriptionRow();
					extractDescriptionRow(rs, resultRow);
					finished = true;
				}
			}
			return resultRow;
		}
	}
}
