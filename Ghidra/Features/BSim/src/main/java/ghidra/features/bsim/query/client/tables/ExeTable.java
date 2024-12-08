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
import java.text.SimpleDateFormat;
import java.time.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.client.AbstractSQLFunctionDatabase;
import ghidra.features.bsim.query.client.RowKeySQL;
import ghidra.features.bsim.query.description.*;

public class ExeTable extends SQLComplexTable {

	public static final String TABLE_NAME = "exetable";

	//@formatter:off
	private static final String CREATE_STMT =
		"CREATE TABLE " + TABLE_NAME + 
		" (id SERIAL PRIMARY KEY,md5 TEXT UNIQUE,name_exec TEXT,architecture INTEGER," + 
		" name_compiler INTEGER,ingest_date TIMESTAMP WITH TIME ZONE,repository INTEGER," + 
		" path INTEGER)";
	
	private static final String INSERT_STMT =
		"INSERT INTO " + TABLE_NAME + 
		" (id,md5,name_exec,architecture,name_compiler,ingest_date,repository,path)" +
		" VALUES(DEFAULT,?,?,?,?,?,?,?) ";

	private static final String SELECT_BY_NAME_STMT =
		"SELECT ALL id,md5,name_exec,architecture,name_compiler,extract(epoch from ingest_date),repository,path" +
		" FROM " + TABLE_NAME +
		" WHERE name_exec = ? " +
		" LIMIT ?";

	private static final String SELECT_BY_ID_STMT =
		"SELECT ALL id,md5,name_exec,architecture,name_compiler,extract(epoch from ingest_date),repository,path" +
		" FROM " + TABLE_NAME + 
		" WHERE id = ?";

	private static final String SELECT_BY_MD5_STMT =
		"SELECT ALL id,md5,name_exec,architecture,name_compiler,extract(epoch from ingest_date),repository,path" +
		" FROM " + TABLE_NAME + 
		" WHERE md5 = ?";

	//@formatter:on

	private final SQLStringTable archtable;
	private final SQLStringTable compilertable;
	private final SQLStringTable repositorytable;
	private final SQLStringTable pathtable;

	private final ExeToCategoryTable exeCategoryTable;

	public static enum ExeTableOrderColumn {
		MD5, NAME
	}

	public static class ExecutableRow {
		public long rowid;
		public String md5;
		public String exename;
		public long arch_id;
		public long compiler_id;
		public long date_milli;
		public long repo_id;
		public long path_id;
	}

	private final CachedStatement<PreparedStatement> insertRowStatement = new CachedStatement<>();
	private final CachedStatement<PreparedStatement> selectByIdStatement = new CachedStatement<>();
	private final CachedStatement<PreparedStatement> selectByMd5Statement = new CachedStatement<>();
	private final CachedStatement<PreparedStatement> selectByNameStatement =
		new CachedStatement<>();

	/**
	 * Constructor
	 * 
	 * @param archtable the architecture table
	 * @param compilertable the compiler table
	 * @param repositorytable the repository table
	 * @param pathtable the path table
	 * @param exeCategoryTable the category table
	 */
	public ExeTable(SQLStringTable archtable, SQLStringTable compilertable,
		SQLStringTable repositorytable, SQLStringTable pathtable,
		ExeToCategoryTable exeCategoryTable) {
		super(TABLE_NAME, "id");
		this.archtable = archtable;
		this.compilertable = compilertable;
		this.repositorytable = repositorytable;
		this.pathtable = pathtable;
		this.exeCategoryTable = exeCategoryTable;
	}

	@Override
	public void close() {
		insertRowStatement.close();
		selectByIdStatement.close();
		selectByMd5Statement.close();
		selectByNameStatement.close();
		super.close();
	}

	@Override
	public void create(Statement st) throws SQLException {
		st.executeUpdate(CREATE_STMT);
	}

	@Override
	public void drop(Statement st) throws SQLException {
		throw new UnsupportedOperationException("ExeTable may not be dropped");
	}

	@Override
	public int delete(long id) throws SQLException {
		int rowcount = super.delete(id);
		if (rowcount == 0) {
			throw new SQLException("Could not delete executable record");
		}
		if (rowcount > 1) {
			throw new SQLException("Problem deleting executable record");
		}
		return rowcount;
	}

	/**
	 * Pulls information out of the given {@link ExecutableRow} object into the given
	 * {@link ResultSet}
	 * 
	 * @param pgres the result set
	 * @param res the executable row
	 * @throws SQLException if there is a problem parsing the result set
	 */
	protected static void extractExecutableRow(ResultSet pgres, ExecutableRow res)
		throws SQLException {
		res.rowid = pgres.getInt(1);
		res.md5 = pgres.getString(2);
		res.exename = pgres.getString(3);
		res.arch_id = pgres.getInt(4);
		res.compiler_id = pgres.getInt(5);
		res.date_milli = (long) (pgres.getDouble(6) * 1000.0);
		res.repo_id = pgres.getInt(7);
		res.path_id = pgres.getInt(8);
	}

	/**
	 * Creates {@link ExecutableRecord} objects from {@link ResultSet} and stores
	 * them in the given list.
	 * 
	 * @param rs the result set
	 * @param vecres the list of executable records
	 * @param res the description manager
	 * @param max the max number of rows to return
	 * @return the number of rows returned
	 * @throws SQLException if there is an problem parsing the result set
	 * @throws LSHException if there is an problem creating the executable record
	 */
	public int extractExecutableRows(ResultSet rs, List<ExecutableRecord> vecres,
		DescriptionManager res, int max) throws SQLException, LSHException {

		// Assume the sql statement is returning some number of exetable rows
		// Read all these rows and create corresponding ExecutableRecord objects
		List<ExecutableRow> exerows = new ArrayList<>();
		boolean finished = false;

		while (rs.next()) {
			if (!finished) {
				ExecutableRow row = new ExecutableRow();
				exerows.add(row);
				extractExecutableRow(rs, row);
				if ((max > 0) && (exerows.size() >= max)) {
					finished = true;
				}
			}
		}

		for (ExecutableRow exerow : exerows) {
			ExecutableRecord exerec = makeExecutableRecord(res, exerow);
			if (vecres != null) {
				vecres.add(exerec);
			}
		}
		return exerows.size();
	}

	/**
	 * Make an ExecutableRecord within the DescriptionManager container, given
	 * database row information
	 * 
	 * @param manager is the DescriptionManager that will contain the new record
	 * @param row is the columnar values for the executable from the database
	 * @return the new ExecutableRecord
	 * @throws SQLException if there is a problem parsing the table objects
	 * @throws LSHException if there is a problem creating a new exec library or record
	 */
	public ExecutableRecord makeExecutableRecord(DescriptionManager manager, ExecutableRow row)
		throws SQLException, LSHException {
		String arch = archtable.getString(row.arch_id);

		ExecutableRecord exerec;
		RowKeySQL rowid = new RowKeySQL(row.rowid);
		if (ExecutableRecord.isLibraryHash(row.md5)) {
			exerec = manager.newExecutableLibrary(row.exename, arch, rowid);
		}
		else {
			String cname = compilertable.getString(row.compiler_id);
			String repo = repositorytable.getString(row.repo_id);
			String path = pathtable.getString(row.path_id);
			Date date = new Date(row.date_milli);
			exerec = manager.newExecutableRecord(row.md5, row.exename, cname, arch, date, repo,
				path, rowid);
		}
		return exerec;
	}

	/**
	 * Query for a unique executable based on -name- and possibly other metadata
	 * 
	 * @param manage the container to store the result
	 * @param name the name the executable must match
	 * @param arch the architecture the executable must match (may be zero length)
	 * @param cname the compiler name the executable must match (may be zero length)
	 * @return the unique resulting ExecutableRecord or null, if none or more
	 *         than 1 is found
	 * @throws SQLException if there is a problem querying for the executable name
	 * @throws LSHException if there is a problem querying for the executable name or transferring the exec
	 */
	public ExecutableRecord querySingleExecutable(DescriptionManager manage, String name,
		String arch, String cname) throws SQLException, LSHException {
		DescriptionManager tmp = new DescriptionManager();
		queryNameExeMatch(null, tmp, name, 2000000);
		ExecutableRecord res = null;
		int count = 0;

		for (ExecutableRecord erec : tmp.getExecutableRecordSet()) {
			if (!StringUtils.isBlank(arch)) {
				if (!erec.getArchitecture().equals(arch)) {
					continue;
				}
			}
			if (!StringUtils.isBlank(cname)) {
				if (!erec.getNameCompiler().equals(cname)) {
					continue;
				}
			}
			res = erec;
			count += 1;
			if (count > 1) {
				return null; // More than one match
			}
		}
		if (count != 1) {
			return null; // No matches
		}
		return manage.transferExecutable(res);
	}

	/**
	 * Executes a database query to return a list of records matching an executalble name 
	 * filter.
	 * 
	 * @param vecres the list of executable records to populate
	 * @param res the description manager
	 * @param nm the name to query for
	 * @param max the max number of records to return
	 * @return the number of records returned
	 * @throws SQLException if there is a problem creating the query statement
	 * @throws LSHException if there is a problem extracting executable rows
	 */
	public int queryNameExeMatch(List<ExecutableRecord> vecres, DescriptionManager res,
		String nm, int max) throws SQLException, LSHException {
		PreparedStatement s =
			selectByNameStatement.prepareIfNeeded(() -> db.prepareStatement(SELECT_BY_NAME_STMT));
		s.setString(1, nm);
		s.setInt(2, max > 0 ? max : 2000000);
		s.setFetchSize(50);
		int count = 0;
		try (ResultSet rs = s.executeQuery()) {
			count = extractExecutableRows(rs, vecres, res, max);
		}
		return count;
	}

	/**
	 * Query for a single executable based on its exetable -id-
	 * 
	 * @param id the exetable id
	 * @return the executable row
	 * @throws SQLException if there is a problem creating or executing the query
	 */
	public ExecutableRow querySingleExecutableId(long id) throws SQLException {

		PreparedStatement s =
			selectByIdStatement.prepareIfNeeded(() -> db.prepareStatement(SELECT_BY_ID_STMT));
		s.setInt(1, (int) id);
		try (ResultSet rs = s.executeQuery()) {
			if (!rs.next()) {
				throw new SQLException("Bad exetable rowid");
			}
			ExecutableRow row = new ExecutableRow();
			extractExecutableRow(rs, row);
			return row;
		}
	}

	/**
	 * Return the executable with matching md5 (if any)
	 * 
	 * @param md5 the md5 hash to query
	 * @return the ExecutableRow data or null
	 * @throws SQLException if there is a problem creating or executing the query
	 */
	public ExecutableRow queryMd5ExeMatch(String md5) throws SQLException {

		PreparedStatement s =
			selectByMd5Statement.prepareIfNeeded(() -> db.prepareStatement(SELECT_BY_MD5_STMT));
		s.setString(1, md5);
		try (ResultSet rs = s.executeQuery()) {
			if (!rs.next()) { // If there are no matching rows
				return null;
			}
			ExecutableRow row = new ExecutableRow();
			extractExecutableRow(rs, row);
			return row;
		}
	}

	/**
	 * Returns a count of all records in the database matching the filter criteria.
	 * 
	 * @param filterMd5 md5 must contain this
	 * @param filterExeName exe name must contain this
	 * @param filterArch if non-zero, force matching architecture id
	 * @param filterCompilerName if non-zero, force matching compiler id
	 * @param includeFakes if true, include MD5s that start with 'bbbbbbbbaaaaaaa'
	 * @return total number of records in the database
	 * @throws SQLException when preparing or executing the query
	 */
	public int queryExeCount(String filterMd5, String filterExeName, long filterArch,
		long filterCompilerName, boolean includeFakes) throws SQLException {

		if (StringUtils.isAnyBlank(filterMd5)) {
			filterMd5 = null;
		}
		if (StringUtils.isAnyBlank(filterExeName)) {
			filterExeName = null;
		}

		StringBuilder buffer = new StringBuilder();
		buffer.append("SELECT ALL COUNT(*) FROM ");
		buffer.append(TABLE_NAME);
		buffer.append(" ");
		if (filterMd5 != null || filterExeName != null || filterArch != 0 ||
			filterCompilerName != 0 || !includeFakes) {
			buffer.append("WHERE (");
			boolean needAnd = false;
			if (!includeFakes) {
				buffer.append("md5 NOT ILIKE 'bbbbbbbbaaaaaaaa%' ");
				needAnd = true;
			}
			if (filterMd5 != null) {
				if (needAnd) {
					buffer.append("AND ");
				}
				if (filterMd5.length() == 32) {	// A complete md5 value
					buffer.append("md5 = ? ");
				}
				else {						// A partial md5 prefix
					buffer.append("md5 ILIKE ? ");
					filterMd5 = filterMd5 + '%';	// match anything at the end	
				}
				needAnd = true;
			}
			if (filterExeName != null) {
				if (needAnd) {
					buffer.append("AND ");
				}
				buffer.append("name_exec ILIKE ? ");
				filterExeName = '%' + filterExeName + '%';
				needAnd = true;
			}
			if (filterArch != 0) {
				if (needAnd) {
					buffer.append("AND ");
				}
				buffer.append("architecture = ? ");
				needAnd = true;
			}
			if (filterCompilerName != 0) {
				if (needAnd) {
					buffer.append("AND ");
				}
				buffer.append("name_compiler = ? ");
			}
			buffer.append(')');
		}

		int pos = 1;
		String query = buffer.toString();
		try (PreparedStatement selectExeCountStatement = db.prepareStatement(query)) {
			if (filterMd5 != null) {
				selectExeCountStatement.setString(pos++, filterMd5);
			}
			if (filterExeName != null) {
				selectExeCountStatement.setString(pos++, filterExeName);
			}
			if (filterArch != 0) {
				selectExeCountStatement.setInt(pos++, (int) filterArch);
			}
			if (filterCompilerName != 0) {
				selectExeCountStatement.setInt(pos++, (int) filterCompilerName);
			}

			try (ResultSet rs = selectExeCountStatement.executeQuery()) {
				rs.next();
				int count = rs.getInt(1);
				return count;
			}
			catch (Exception e) {
				return 0;
			}
		}
	}

	/**
	 * Returns a list of all rows in the exe table matching a given filter.
	 * 
	 * @param limit the max number of results to return
	 * @param filterMd5 md5 must contain this
	 * @param filterExeName exe name must contain this
	 * @param filterArch if non-zero architecture must match this id
	 * @param filterCompilerName if non-zero compiler must match this id
	 * @param sortColumn the name of the column that should define the sorting order
	 * @param includeFakes if false, will exclude generated MD5s starting with "bbbbbbbbaaaaaaaa"
	 * @return list of executables
	 * @throws SQLException when preparing or executing the query
	 */
	public List<ExecutableRow> queryAllExe(int limit, String filterMd5, String filterExeName,
		long filterArch, long filterCompilerName, ExeTableOrderColumn sortColumn,
		boolean includeFakes) throws SQLException {

		if (StringUtils.isAnyBlank(filterMd5)) {
			filterMd5 = null;
		}
		if (StringUtils.isAnyBlank(filterExeName)) {
			filterExeName = null;
		}
		StringBuilder buffer = new StringBuilder();
		buffer.append(
			"SELECT ALL id,md5,name_exec,architecture,name_compiler,extract(epoch from ingest_date),repository,path FROM ");
		buffer.append(TABLE_NAME);
		buffer.append(" ");
		if (filterMd5 != null || filterExeName != null || filterArch != 0 ||
			filterCompilerName != 0 || !includeFakes) {
			buffer.append("WHERE (");
			boolean needAnd = false;
			if (!includeFakes) {
				buffer.append("md5 NOT ILIKE 'bbbbbbbbaaaaaaaa%' ");
				needAnd = true;
			}
			if (filterMd5 != null) {
				if (needAnd) {
					buffer.append("AND ");
				}
				if (filterMd5.length() == 32) {	// A complete md5 value
					buffer.append("md5 = ? ");
				}
				else {						// A partial md5 prefix
					buffer.append("md5 ILIKE ? ");
					filterMd5 = filterMd5 + '%';	// match anything at the end	
				}
				needAnd = true;
			}
			if (filterExeName != null) {
				if (needAnd) {
					buffer.append("AND ");
				}
				buffer.append("name_exec ILIKE ? ");
				filterExeName = '%' + filterExeName + '%';
				needAnd = true;
			}
			if (filterArch != 0) {
				if (needAnd) {
					buffer.append("AND ");
				}
				buffer.append("architecture = ? ");
				needAnd = true;
			}
			if (filterCompilerName != 0) {
				if (needAnd) {
					buffer.append("AND ");
				}
				buffer.append("name_compiler = ? ");
			}
			buffer.append(')');
		}
		if (sortColumn == ExeTableOrderColumn.NAME) {
			buffer.append(" ORDER BY name_exec ");
		}
		else {
			buffer.append(" ORDER BY md5 ");
		}
		buffer.append("LIMIT ?");

		int pos = 1;
		String query = buffer.toString();
		try (PreparedStatement selectAllExeStatement = db.prepareStatement(query)) {
			if (filterMd5 != null) {
				selectAllExeStatement.setString(pos++, filterMd5);
			}
			if (filterExeName != null) {
				selectAllExeStatement.setString(pos++, filterExeName);
			}
			if (filterArch != 0) {
				selectAllExeStatement.setInt(pos++, (int) filterArch);
			}
			if (filterCompilerName != 0) {
				selectAllExeStatement.setInt(pos++, (int) filterCompilerName);
			}
			selectAllExeStatement.setInt(pos, limit);

			try (ResultSet rs = selectAllExeStatement.executeQuery()) {
				List<ExecutableRow> executables = new ArrayList<>();
				while (rs.next()) {
					ExecutableRow row = new ExecutableRow();
					executables.add(row);
					extractExecutableRow(rs, row);
				}

				return executables;
			}
		}
	}

	@Override
	public long insert(Object... arguments) throws SQLException {

		if (arguments == null || arguments.length != 1 ||
			!(arguments[0] instanceof ExecutableRecord)) {
			throw new IllegalArgumentException(
				"Insert method for ExeTable must take exactly one ExecutableRecord argument");
		}

		ExecutableRecord erec = (ExecutableRecord) arguments[0];
		PreparedStatement s = insertRowStatement.prepareIfNeeded(
			() -> db.prepareStatement(INSERT_STMT, Statement.RETURN_GENERATED_KEYS));
		long arch_id = archtable.writeString(erec.getArchitecture());
		long compiler_id = compilertable.writeString(erec.getNameCompiler());
		long repo_id = repositorytable.writeString(erec.getRepository());
		long path_id = pathtable.writeString(erec.getPath());
		long milli = erec.getDate().getTime();

		OffsetDateTime odt =
			OffsetDateTime.ofInstant(Instant.ofEpochMilli(milli), ZoneId.systemDefault());

		s.setString(1, erec.getMd5());
		s.setString(2, erec.getNameExec());
		s.setInt(3, (int) arch_id);
		s.setInt(4, (int) compiler_id);
		s.setObject(5, odt);
		s.setInt(6, (int) repo_id);
		s.setInt(7, (int) path_id);

		s.executeUpdate();
		try (ResultSet rs = s.getGeneratedKeys()) {
			if (!rs.next()) {
				throw new SQLException("Did not get exetable sequence number after insertion");
			}
			long rowid = rs.getLong(1);
			return rowid;
		}
	}

	/**
	 * Updates records in the database with information in the given {@link ExecutableRecord}.
	 * 
	 * @param rec the executable record to update
	 * @throws SQLException if there is a problem creating or executing the query
	 */
	public void updateExecutable(ExecutableRecord.Update rec) throws SQLException {
		if (rec.architecture || rec.date || rec.name_compiler || rec.name_exec || rec.path ||
			rec.repository) {

			try (Statement st = db.createStatement()) {
				StringBuilder buf = new StringBuilder();
				boolean previous = false;
				buf.append("UPDATE ");
				buf.append(TABLE_NAME);
				buf.append(" SET ");
				if (rec.name_exec) {
					if (previous) {
						buf.append(',');
					}
					else {
						previous = true;
					}
					buf.append("name_exec='");
					AbstractSQLFunctionDatabase.appendEscapedLiteral(buf, rec.update.getNameExec());
					buf.append('\'');
				}
				if (rec.architecture) {
					long arch_id = archtable.writeString(rec.update.getArchitecture());
					if (previous) {
						buf.append(',');
					}
					else {
						previous = true;
					}
					buf.append("architecture=");
					buf.append(arch_id);
				}
				if (rec.name_compiler) {
					long comp_id = compilertable.writeString(rec.update.getNameCompiler());
					if (previous) {
						buf.append(',');
					}
					else {
						previous = true;
					}
					buf.append("name_compiler=");
					buf.append(comp_id);
				}
				if (rec.date) {
					if (previous) {
						buf.append(',');
					}
					else {
						previous = true;
					}
					String dateString =
						new SimpleDateFormat(AbstractSQLFunctionDatabase.JAVA_TIME_FORMAT)
							.format(rec.update.getDate());
					buf.append("ingest_date=to_timestamp('");
					// Using PostgreSQL compatible to_timestamp formatting options 
					buf.append(dateString)
						.append("','" + AbstractSQLFunctionDatabase.SQL_TIME_FORMAT + "')");
				}
				if (rec.repository) {
					long repo_id = repositorytable.writeString(rec.update.getRepository());
					if (previous) {
						buf.append(',');
					}
					else {
						previous = true;
					}
					buf.append("repository=");
					buf.append(repo_id);
				}
				if (rec.path) {
					long path_id = pathtable.writeString(rec.update.getPath());
					if (previous) {
						buf.append(',');
					}
					else {
						previous = true;
					}
					buf.append("path=");
					buf.append(path_id);
				}
				buf.append(" WHERE id = ");
				buf.append(rec.update.getRowId().getLong());

				st.executeUpdate(buf.toString());
			}
		}

		if (rec.categories) { // Change must be made to categories
			List<CategoryRecord> insertlist = rec.catinsert;
			if (insertlist == null) { // A null is a flag for full deletion,
				// followed by full insertion
				exeCategoryTable.delete(rec.update.getRowId().getLong());
				insertlist = rec.update.getAllCategories();
			}
			if (insertlist != null) {
				for (CategoryRecord element : insertlist) {
					exeCategoryTable.insert(element, rec.update.getRowId().getLong());
				}
			}
		}
	}
}
