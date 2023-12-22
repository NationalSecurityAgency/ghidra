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
package ghidra.features.bsim.query.client;

import java.sql.*;
import java.util.*;
import java.util.Date;

import org.apache.commons.lang3.StringUtils;

import generic.lsh.vector.*;
import ghidra.features.bsim.gui.filters.FunctionTagBSimFilterType;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.client.tables.*;
import ghidra.features.bsim.query.client.tables.CallgraphTable.CallgraphRow;
import ghidra.features.bsim.query.client.tables.DescriptionTable.DescriptionRow;
import ghidra.features.bsim.query.client.tables.ExeTable.ExeTableOrderColumn;
import ghidra.features.bsim.query.client.tables.ExeTable.ExecutableRow;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.protocol.*;
import ghidra.util.Msg;

/**
 * Defines the BSim {@link FunctionDatabase} backed by an SQL database.
 * 
 * Simple, one-column tables that only contain string data use the
 * {@link SQLStringTable} class and are defined in this class. More complex
 * tables are defined in their own classes in the
 * {@link ghidra.features.bsim.query.client.tables} package.
 * 
 * @param <VF> {@link LSHVectorFactory vector factory} implementation class
 */
public abstract class AbstractSQLFunctionDatabase<VF extends LSHVectorFactory>
		implements SQLFunctionDatabase {

	public static final String SQL_TIME_FORMAT = "YYYY-MM-DD HH24:MI:SS.MSz";
	public static final String JAVA_TIME_FORMAT = "yyyy-MM-dd HH:mm:ss.SSSZ";

	//private static final 

	private static final String ARCH_TABLE_NAME = "archtable";
	private static final String COMPILER_TABLE_NAME = "comptable";
	private static final String REPOSITORY_TABLE_NAME = "repotable";
	private static final String PATH_TABLE_NAME = "pathtable";
	private static final String CAT_STRING_TABLE_NAME = "catstringtable";

	protected final BSimJDBCDataSource ds;

	// Indicates the version of the db table configuration.  This needs to be updated
	// whenever changes are made to the table structure.  A value less-than 0 is ignored
	// and disables check (e.g., transient in-memory database).
	public final int supportedLayoutVersion;

	/**
	 * Main connection to database established by call to {@link #initConnection()}
	 */
	private Connection db = null;

	/**
	 * Database Information established by {@link #createDatabase(Configuration)} or
	 * {@link #initializeDatabase(Configuration)}
	 */
	private DatabaseInformation info;

	// Define all the db tables.
	private ExeTable exeTable;
	private ExeToCategoryTable exeCategoryTable;
	private DescriptionTable descTable;
	private CallgraphTable callgraphTable;

	private SQLStringTable archtable;
	private SQLStringTable compilertable;
	private SQLStringTable repositorytable;
	private SQLStringTable pathtable;
	private SQLStringTable catstringtable;

	private IdfLookupTable idfLookupTable;
	private WeightTable weightTable;

	protected final VF vectorFactory;	// Factory used to generate LSHVector objects

	private Error lasterror;
	private Status status;
	private boolean isinit;

	private KeyValueTable keyValueTable; // used for storing DatabaseInformation

	private OptionalTable[] optionaltables = null;

	private boolean trackcallgraph = true;

	protected AbstractSQLFunctionDatabase(BSimJDBCDataSource ds, VF vectorFactory,
			int supportedLayoutVersion) {
		this.ds = ds;
		this.supportedLayoutVersion = supportedLayoutVersion;
		this.vectorFactory = vectorFactory;

		archtable = new SQLStringTable(ARCH_TABLE_NAME, 1000);
		compilertable = new SQLStringTable(COMPILER_TABLE_NAME, 1000);
		repositorytable = new SQLStringTable(REPOSITORY_TABLE_NAME, 1000);
		pathtable = new SQLStringTable(PATH_TABLE_NAME, 1000);
		catstringtable = new SQLStringTable(CAT_STRING_TABLE_NAME, 1000);

		callgraphTable = new CallgraphTable();
		exeCategoryTable = new ExeToCategoryTable(catstringtable);
		keyValueTable = new KeyValueTable();
		exeTable =
			new ExeTable(archtable, compilertable, repositorytable, pathtable, exeCategoryTable);
		descTable = new DescriptionTable(exeTable);

		weightTable = new WeightTable();
		idfLookupTable = new IdfLookupTable();

		lasterror = null;
		info = null;
		status = Status.Unconnected;
		isinit = false;
	}

	@Override
	public void close() {

		weightTable.close();
		idfLookupTable.close();

		archtable.close();
		compilertable.close();
		repositorytable.close();
		pathtable.close();
		catstringtable.close();

		callgraphTable.close();
		exeCategoryTable.close();
		keyValueTable.close();
		exeTable.close();
		descTable.close();

		if (optionaltables != null) {
			for (OptionalTable table : optionaltables) {
				table.close();
			}
			optionaltables = null;
		}

		if (db != null) {
			closing(db);
			try {
				db.close();
			}
			catch (SQLException e) {
				e.printStackTrace();
			}
			db = null;
		}
		status = Status.Unconnected;

		isinit = false;
		info = null;
	}

	/**
	 * Perform any required cleanup prior to connection close.
	 * Partial cleanup has already been performed.
	 * @param c database connection
	 */
	protected void closing(Connection c) {
		// do nothing by default
	}

	/**
	 * Establish PostgreSQL DB pooled {@link Connection} for this instance.
	 * @return database connection
	 * @throws SQLException if error occurs obtaining connection
	 */
	protected Connection initConnection() throws SQLException {
		if (db == null) {
			db = ds.getConnection();
		}
		return db;
	}

	/**
	 * Start a transaction which will not be auto-committed.  The {@link #endTransaction(boolean)}
	 * method must be invoked when the transaction has completed or failed and should be performed
	 * within a finally block.
	 * @param lockTablesForWrite if true a table lock will be placed which will clear when 
	 * {@link #endTransaction(boolean)} is invoked.
	 * @return the connection associated with the transaction
	 * @throws SQLException if an error occurs
	 */
	protected Connection beginTransaction(boolean lockTablesForWrite) throws SQLException {
		db.setAutoCommit(false);
		if (lockTablesForWrite) {
			lockTablesForWrite();
		}
		return db;
	}

	/**
	 * Lock appropriate tables during complex write/update operation
	 * @throws SQLException if an error occurs 
	 */
	protected void lockTablesForWrite() throws SQLException {
		// do nothing
	}

	/**
	 * End a transaction which was started with {@link #beginTransaction(boolean)} and return
	 * DB connection to an auto-commit state.
	 * @param commit true if transaction should be commited, false to force a rollback.
	 * @throws SQLException if an error occurs 
	 */
	protected void endTransaction(boolean commit) throws SQLException {
		if (commit) {
			db.commit();
		}
		else {
			db.rollback();
		}
		db.setAutoCommit(true);
	}

	/**
	 * @param erec the exectuable record representing the exec to delete
	 * @param funclist list of functions to remove from the callgraph table
	 * @param hasCategories if true, deletes entries from the category table
	 * @return the number of rows deleted
	 * @throws SQLException if there's an error deleting rows
	 */
	private int deleteExecutable(ExecutableRecord erec, List<FunctionDescription> funclist,
			boolean hasCategories) throws SQLException {

		if (hasCategories) {
			exeCategoryTable.delete(erec.getRowId().getLong());
		}
		if (trackcallgraph) {
			for (FunctionDescription element : funclist) {
				callgraphTable.delete(element.getId().getLong());
			}
		}
		return deleteExeRows(erec);
	}

	/**
	 * 
	 * @param erec the executable record to delete
	 * @return the number of rows deleted
	 * @throws SQLException if there is an error removing from the 
	 */
	private int deleteExeRows(ExecutableRecord erec) throws SQLException {

		long rowid = erec.getRowId().getLong();
		final int delcount = descTable.delete(rowid);
		exeTable.delete(rowid); // don't need to save the return value
		return delcount;
	}

	/**
	 * 
	 * @param dbIndo the database information object
	 * @throws SQLException if there is an error parsing the key/value table
	 */
	private void readExecutableCategories(DatabaseInformation dbIndo) throws SQLException {
		int count = Integer.parseInt(keyValueTable.getValue("execatcount"));
		if (count <= 0) {
			dbIndo.execats = null;
			return;
		}
		dbIndo.execats = new ArrayList<String>();
		for (int i = 0; i < count; ++i) {
			String key = "execat" + Integer.toString(i + 1);
			String value = keyValueTable.getValue(key);
			dbIndo.execats.add(value);
		}
	}

	/**
	 * @param dbInfo the database information object
	 * @throws SQLException if there is an error parsing the key/value table
	 */
	private void readFunctionTags(DatabaseInformation dbInfo) throws SQLException {
		String countString = keyValueTable.getValue("functiontagcount");
		int count;
		if (countString != null) {
			count = Integer.parseInt(countString);
		}
		else {
			count = 0;				// key may not be present,  assume 0 tags
		}
		if (count <= 0) {
			dbInfo.functionTags = null;
			return;
		}
		dbInfo.functionTags = new ArrayList<String>();
		for (int i = 0; i < count; ++i) {
			String key = "functiontag" + (i + 1);
			String value = keyValueTable.getValue(key);
			dbInfo.functionTags.add(value);
		}
	}

	/**
	 * Parse <code>keyValueTable</code> data into a {@link DatabaseInformation} object.
	 * @return a database information object
	 * @throws SQLException if there is an error parsing the key/value table
	 */
	private DatabaseInformation parseDatabaseInfo() throws SQLException {
		DatabaseInformation dbInfo = new DatabaseInformation();
		dbInfo.databasename = keyValueTable.getValue("name");
		dbInfo.owner = keyValueTable.getValue("owner");
		dbInfo.description = keyValueTable.getValue("description");
		dbInfo.major = (short) Integer.parseInt(keyValueTable.getValue("major"));
		dbInfo.minor = (short) Integer.parseInt(keyValueTable.getValue("minor"));
		dbInfo.settings = Integer.parseInt(keyValueTable.getValue("settings"));
		String val = keyValueTable.getValue("readonly");
		dbInfo.readonly = false;
		if (val.length() > 0) {
			dbInfo.readonly = (val.charAt(0) == 't');
		}
		val = keyValueTable.getValue("trackcallgraph");
		dbInfo.trackcallgraph = false;
		if (val.length() > 0) {
			dbInfo.trackcallgraph = (val.charAt(0) == 't');
		}
		try {
			dbInfo.layout_version = Integer.parseInt(keyValueTable.getValue("layout"));
		}
		catch (SQLException exception) { // If this is an old layout, it may
			// not have this key
			dbInfo.layout_version = 0; // In which case, we know it is version 0
		}
		dbInfo.dateColumnName = keyValueTable.getValue("datecolumn");
		if (dbInfo.dateColumnName.equals("Ingest Date")) {
			// name
			dbInfo.dateColumnName = null; // Don't bother holding it
		}
		readExecutableCategories(dbInfo);
		readFunctionTags(dbInfo);
		return dbInfo;
	}

	/**
	 * Initialize table state and {@code config} from existing database.
	 * NOTE: it is left to specific implementation to override this method to properly
	 * initialize default {@code config.weightfactory } and {@code config.idflookup }.
	 * @param config the database configuration
	 * @throws SQLException if there is a problem opening the database connection
	 */
	protected void initializeDatabase(Configuration config) throws SQLException {

		initConnection();
		setConnectionOnTables(db);

		try (Statement st = db.createStatement()) {

			config.info = parseDatabaseInfo();
			config.k = Integer.parseInt(keyValueTable.getValue("k"));
			config.L = Integer.parseInt(keyValueTable.getValue("L"));
			config.weightfactory = new WeightFactory();
			config.idflookup = new IDFLookup();

			trackcallgraph = config.info.trackcallgraph;
		}

		weightTable.recoverWeights(config.weightfactory);
		idfLookupTable.recoverIDFLookup(config.idflookup);
	}

	/**
	 * Generate new empty database which corresponds to {@link #ds}.  
	 * A new connection may be used to the default database
	 * so that a new database may be created.
	 * @throws SQLException if an error occurs while creating the database
	 */
	protected abstract void generateRawDatabase() throws SQLException;

	/**
	 * Generate tables and initialize state for a new database.
	 * @param config the database configuration
	 * @throws SQLException if there is aproblem opening a connectino to the database
	 */
	protected void createDatabase(Configuration config) throws SQLException {
		generateRawDatabase();
		trackcallgraph = config.info.trackcallgraph;

		initConnection();
		setConnectionOnTables(db);

		try (Statement st = db.createStatement()) {
			beginTransaction(false);
			boolean commit = false;
			try {
				archtable.createTable();
				compilertable.createTable();
				repositorytable.createTable();
				pathtable.createTable();
				catstringtable.createTable();

				keyValueTable.create(st);
				keyValueTable.writeBasicInfo(config.info);
				keyValueTable.insert("k", Integer.toString(config.k));
				keyValueTable.insert("L", Integer.toString(config.L));
				commit = true;
			}
			finally {
				endTransaction(commit);
			}

			exeCategoryTable.create(st);
			exeTable.create(st);
			descTable.create(st);

			if (trackcallgraph) {
				callgraphTable.create(st);
			}

			installWeights(db, config.weightfactory);
			installIDFLookup(db, config.idflookup);
		}
		catch (final SQLException err) {
			throw new SQLException("Could not create database: " + err.getMessage());
		}
	}

	protected void setConnectionOnTables(Connection db) {

		weightTable.setConnection(db);
		idfLookupTable.setConnection(db);

		archtable.setConnection(db);
		compilertable.setConnection(db);
		repositorytable.setConnection(db);
		pathtable.setConnection(db);
		catstringtable.setConnection(db);

		callgraphTable.setConnection(db);
		exeCategoryTable.setConnection(db);
		keyValueTable.setConnection(db);
		exeTable.setConnection(db);
		descTable.setConnection(db);
	}

	/**
	 * Installs/Replaces Weight Table
	 * @param factory the weight factory
	 * @throws SQLException if there is an error creating the database query
	 */
	private void installWeights(Connection conn, WeightFactory factory) throws SQLException {
		try (Statement st = conn.createStatement()) {
			weightTable.drop(st);
			weightTable.create(st);

			double[] weightArray = factory.toArray();
			beginTransaction(false);
			boolean commit = false;
			try {
				for (int i = 0; i < weightArray.length; ++i) {
					weightTable.insert(i, weightArray[i]);
				}
				commit = true;
			}
			finally {
				endTransaction(commit);
			}
		}
	}

	/**
	 * Installs/Replaces the IDF Lookup table
	 * @param lookup the IDF lookup
	 * @throws SQLException if there is an error creating the database query
	 */
	private void installIDFLookup(Connection conn, IDFLookup lookup) throws SQLException {
		try (Statement st = conn.createStatement()) {
			idfLookupTable.drop(st);
			idfLookupTable.create(st);

			int[] intArray = lookup.toArray();
			beginTransaction(false);
			boolean commit = false;
			try {
				for (int i = 0; i < intArray.length; i += 2) {
					idfLookupTable.insert(intArray[i + 1], intArray[i]);
				}
				commit = true;
			}
			finally {
				endTransaction(commit);
			}
		}
	}

	/**
	 * 
	 * @param rec the function description update object
	 * @throws SQLException if there is a problem creating the query statement
	 */
	private void updateFunction(FunctionDescription.Update rec) throws SQLException {
		try (Statement st = db.createStatement()) {
			StringBuilder buf = new StringBuilder();
			buf.append("UPDATE desctable SET ");
			boolean previous = false;
			if (rec.function_name) {
				previous = true;
				buf.append("name_func='");
				appendEscapedLiteral(buf, rec.update.getFunctionName());
				buf.append('\'');
			}
			if (rec.flags) {
				if (previous) {
					buf.append(',');
				}
				buf.append("flags=");
				buf.append(rec.update.getFlags());
			}
			buf.append(" WHERE id = ");
			buf.append(rec.update.getId().getLong());

			st.executeUpdate(buf.toString());
		}
	}

	/**
	 * Make a temporary ExecutableRecord given database row information. The
	 * record is NOT attached to a DescriptionManager
	 * 
	 * @param row
	 *            is the columnar values for the executable from the database
	 * @return the new temporary ExecutableRecord
	 * @throws SQLException if there is a problem parsing the table objects
	 */
	private ExecutableRecord makeExecutableRecordTemp(ExecutableRow row) throws SQLException {
		String arch = archtable.getString(row.arch_id);
		ExecutableRecord exeres;
		RowKeySQL rowid = new RowKeySQL(row.rowid);
		if (ExecutableRecord.isLibraryHash(row.md5)) {
			exeres = new ExecutableRecord(row.exename, arch, rowid);
		}
		else {
			String cname = compilertable.getString(row.compiler_id);
			String repo = repositorytable.getString(row.repo_id);
			String path = null;
			if (repo != null) {
				path = pathtable.getString(row.path_id);
			}
			exeres = new ExecutableRecord(row.md5, row.exename, cname, arch,
				new Date(row.date_milli), rowid, repo, path);
		}
		return exeres;
	}

	/**
	 * Run through a list of functions: mark any that have been previously
	 * stored to the database by populating the function's rowid in the
	 * corresponding FunctionDescription
	 * 
	 * @param input
	 *            is DescriptionManager containing the functions
	 * @param iter
	 *            is the iterator listing the FunctionDescriptions
	 * @return true if there are ANY new functions, either from new executables,
	 *         or old executables with new functions
	 * @throws SQLException if there is a problem querying the description table
	 */
	private boolean markPreviouslyStoredFunctions(DescriptionManager input,
			Iterator<FunctionDescription> iter) throws SQLException {
		boolean newfuncs = false;

		while (iter.hasNext()) {
			FunctionDescription func = iter.next();
			ExecutableRecord erec = func.getExecutableRecord();
			if (!erec.isAlreadyStored()) {
				newfuncs = true;
				continue;
			}
			DescriptionRow row = descTable.queryFuncNameAddr(erec.getRowId().getLong(),
				func.getFunctionName(), func.getAddress());
			if (row == null) {
				newfuncs = true;
				continue;
			}

			// We could do some consistency checks here between -func- being
			// inserted and -func2- that was already present

			// Set the id, which marks -func- as already stored.
			input.setFunctionDescriptionId(func, new RowKeySQL(row.rowid));
		}
		return newfuncs;
	}

	/**
	 * 
	 * @param value the architecture value
	 * @return the architecture ID
	 * @throws SQLException if there is a problem parsing the architecture value
	 */
	long queryArchString(String value) throws SQLException {
		return archtable.readStringId(value);
	}

	/**
	 * 
	 * @param value the compiler value
	 * @return the compiler ID
	 * @throws SQLException if there is a problem parsing the compiler value
	 */
	long queryCompilerString(String value) throws SQLException {
		return compilertable.readStringId(value);
	}

	/**
	 * 
	 * @param value the repository value
	 * @return the repository ID
	 * @throws SQLException if there is a problem parsing the repository value
	 */
	long queryRepositoryString(String value) throws SQLException {
		return repositorytable.readStringId(value);
	}

	/**
	 * @param value the category value
	 * @return the category ID
	 * @throws SQLException if there is a problem parsing the category value
	 */
	long queryCategoryString(String value) throws SQLException {
		return catstringtable.readStringId(value);
	}

	/**
	 * Query for all functions (up to the limit -max-) of the given -exe-.
	 * Populate DescriptionManager and List and with corresponding FunctionDescription objects
	 * Does NOT populate SignatureRecord or CallGraph parts of the FunctionDescription
	 * @param vecres has all queried functions added to it
	 * @param exe is the executable containing the functions
	 * @param res is the DescriptionManager container for the new records
	 * @param max is the maximum number of records to read
	 * @return the number of function records read
	 * @throws SQLException if there is a problem creating or executing the query
	 */
	private int queryAllFunc(List<FunctionDescription> vecres, ExecutableRecord exe,
			DescriptionManager res, int max) throws SQLException {
		StringBuffer buf = new StringBuffer();
		buf.append("SELECT ALL * FROM desctable WHERE id_exe = ");
		buf.append((int) exe.getRowId().getLong());
		if (max > 0) {
			buf.append(" LIMIT ").append(max);
		}
		try (Statement st = db.createStatement(); ResultSet rs = st.executeQuery(buf.toString())) {
			st.setFetchSize(50);
			int count = 0;
			final List<DescriptionRow> descrow = descTable.extractDescriptionRows(rs, max);
			count = descrow.size();
			descTable.convertDescriptionRows(vecres, descrow, exe, res, null);
			return count;
		}
	}

	/**
	 * Update metadata for the executable -erec- and all its functions (in
	 * manage)
	 * 
	 * @param manage
	 *            is the collection of functions to update
	 * @param erec
	 *            is the root executable
	 * @param badfunc
	 *            collects references to functions with update info that could
	 *            not be identified
	 * @param checkExeCategories if true, update any found executable categories
	 * @return -1 if the executable could not be found, otherwise return 2*# of
	 *         update functions + 1 if the executable metadata is also updated
	 * @throws LSHException if there is a problem transferring the executable to a new container
	 * @throws SQLException if there is a problem executing various queries
	 */
	private int updateExecutable(DescriptionManager manage, ExecutableRecord erec,
			List<FunctionDescription> badfunc, boolean checkExeCategories)
			throws LSHException, SQLException {
		int val;		// The return value
		beginTransaction(true);
		boolean commit = false;
		try {
			ExecutableRow row = exeTable.queryMd5ExeMatch(erec.getMd5());
			if (row == null) {
				return -1; // Indicate that we couldn't find the executable
			}
			ExecutableRecord erec_db = makeExecutableRecordTemp(row);
			DescriptionManager dbmanage = new DescriptionManager();
			erec_db = dbmanage.transferExecutable(erec_db);
			if (checkExeCategories) {
				final List<CategoryRecord> catvec =
					exeCategoryTable.queryExecutableCategories(erec_db.getRowId().getLong(), 100); // Make sure categories are filled in before diff

				dbmanage.setExeCategories(erec_db, catvec);
			}
			ExecutableRecord.Update exe_update = new ExecutableRecord.Update();
			boolean has_exe_update = erec.diffForUpdate(exe_update, erec_db);

			// Load all the functions in the database under this executable
			List<FunctionDescription> funclist = new ArrayList<FunctionDescription>();
			queryAllFunc(funclist, erec_db, dbmanage, 0);

			// Create a map from address to executables
			Map<Long, FunctionDescription> addrmap =
				FunctionDescription.createAddressToFunctionMap(funclist.iterator());

			// Match new functions to old functions via the address
			List<FunctionDescription.Update> updatelist;
			updatelist =
				FunctionDescription.generateUpdates(manage.listFunctions(erec), addrmap, badfunc);

			if (!has_exe_update && updatelist.isEmpty()) {
				return 0; // All updates are in place already
			}

			// Do the actual database updates
			if (has_exe_update) {
				exeTable.updateExecutable(exe_update);
			}
			for (FunctionDescription.Update updateRec : updatelist) {
				updateFunction(updateRec);
			}
			commit = true;
			val = has_exe_update ? 1 : 0;
			val += 2 * updatelist.size();
		}
		finally {
			endTransaction(commit);
		}
		return val;
	}

	/**
	 * Establish an optional key/value table with this connection.
	 * The OptionalTable object is created and added to the list for this connection.
	 * If the caller desires, the table is tested for existence. If it doesn't
	 * exist, the object is not added to the list and null is returned.
	 * @param tableName is the name of the SQL table
	 * @param keyType is the type-code of the key column
	 * @param valueType is the type-code of the value column
	 * @param testExistence if true, we test the existence of the table
	 * @return the OptionalTable or null
	 * @throws SQLException for problems with the connection, or if
	 *     the table exists with different column types
	 */
	private OptionalTable getOptionalTable(String tableName, int keyType, int valueType,
			boolean testExistence) throws SQLException {
		if (optionaltables != null) {		// Search for existing table
			for (OptionalTable table : optionaltables) {
				if (table.getName().equals(tableName)) {
					if (keyType != table.getKeyType() || valueType != table.getValueType()) {
						throw new SQLException("Optional table: column type mismatch");
					}
					return table;
				}
			}
		}
		// If we reach here, table object doesn't exist, so we create it
		OptionalTable table = new OptionalTable(tableName, keyType, valueType, db);
		if (testExistence) {			// If the user requested
			if (!table.exists()) {		//    test for the existence of the table
				table.close();
				return null;			// If it doesn't exist, don't save new table object, return null
			}
		}
		// Insert the new table object at the end of the list
		OptionalTable[] newArray;
		if (optionaltables != null) {
			newArray = Arrays.copyOf(optionaltables, optionaltables.length + 1);
			newArray[optionaltables.length] = table;
		}
		else {
			newArray = new OptionalTable[1];
			newArray[0] = table;
		}
		optionaltables = newArray;
		return table;
	}

	/**
	 * 
	 * @param buf the string builder object
	 * @param str the string to parse
	 * @throws SQLException if there is a zero byte in the string
	 */
	public static void appendEscapedLiteral(StringBuilder buf, String str) throws SQLException {
		for (int i = 0; i < str.length(); ++i) {
			char ch = str.charAt(i);
			if (ch == '\0') {
				throw new SQLException("Zero byte in SQL string");
			}
			if (ch == '\\' || ch == '\'') {
				buf.append(ch);
			}
			buf.append(ch);
		}
	}

	/**
	 * Convert a low-level list of function rows into full FunctionDescription objects
	 * @param simres (optional -- may be null) generate a SimilarityNote for every function
	 * @param descvec is the list of low-level function rows
	 * @param vecres (optional -- may be null) vector result producing these functions
	 * @param res is the DescriptionManager holding the newly generated FunctionDescriptions
	 * @param srec (optional -- may be null) is a description object of the vector
	 * @throws SQLException is there is an error querying tables
	 * @throws LSHException for internal consistency errors
	 */
	protected void convertDescriptionRows(SimilarityResult simres, List<DescriptionRow> descvec,
			VectorResult vecres, DescriptionManager res, SignatureRecord srec)
			throws SQLException, LSHException {
		Iterator<DescriptionRow> iter = descvec.iterator();
		DescriptionRow currow = iter.next();
		RowKey rowKey = new RowKeySQL(currow.id_exe);
		ExecutableRecord curexe = res.findExecutableByRow(rowKey);
		if (curexe == null) {
			ExecutableRow exerow = exeTable.querySingleExecutableId(currow.id_exe);
			curexe = exeTable.makeExecutableRecord(res, exerow);
			res.cacheExecutableByRow(curexe, rowKey);
		}

		FunctionDescription fres =
			DescriptionTable.convertDescriptionRow(currow, curexe, res, srec);
		if (simres != null) {
			simres.addNote(fres, vecres.sim, vecres.signif);
		}
		if (srec != null) {
			res.setSignatureId(srec, currow.id_sig);
		}
		while (iter.hasNext()) {
			currow = iter.next();
			rowKey = new RowKeySQL(currow.id_exe);
			curexe = res.findExecutableByRow(rowKey);
			if (curexe == null) {
				ExecutableRow exerow = exeTable.querySingleExecutableId(currow.id_exe);
				curexe = exeTable.makeExecutableRecord(res, exerow);
				res.cacheExecutableByRow(curexe, rowKey);
			}
			fres = DescriptionTable.convertDescriptionRow(currow, curexe, res, srec);
			if (simres != null) {
				simres.addNote(fres, vecres.sim, vecres.signif);
			}
		}
	}

	/**
	 * For the given -func-, query the database for its children and put their FunctionDescriptions -res-
	 * @param func is the parent FunctionDescription
	 * @param manager is the container DescriptionManager
	 * @param funcmap quick lookup of FunctionDescription objects already in -res-
	 * @throws SQLException if there is a problem querying callgraph table
	 * @throws LSHException if there is a problem querying the description table
	 */
	private void fillinChildren(FunctionDescription func, DescriptionManager manager,
			Map<RowKey, FunctionDescription> funcmap) throws SQLException, LSHException {
		List<CallgraphRow> callvec = callgraphTable.queryCallgraphRows(func, trackcallgraph);
		for (CallgraphRow element : callvec) {
			long id = element.dest;
			RowKey key = new RowKeySQL(id);
			FunctionDescription fdesc = funcmap.get(key);
			if (fdesc == null) {
				fdesc = descTable.querySingleDescriptionId(manager, id);
				funcmap.put(fdesc.getId(), fdesc);
			}
			manager.makeCallgraphLink(func, fdesc, 0);
		}
	}

	/**
	 * 
	 * @param manage the description manager
	 * @throws SQLException if there is a problem querying for executable categories
	 */
	private void fillinExecutableCategories(DescriptionManager manage) throws SQLException {
		TreeSet<ExecutableRecord> exes = manage.getExecutableRecordSet();
		int max = 100; // Max number of categories that can be returned for a single executable
		// TODO: Find better way to manage this and error out if limit exceeded
		for (ExecutableRecord erec : exes) {
			if (erec.categoriesAreSet()) {
				continue; // Categories are already filled in
			}
			List<CategoryRecord> catvec =
				exeCategoryTable.queryExecutableCategories(erec.getRowId().getLong(), max);
			manage.setExeCategories(erec, catvec);
		}
	}

	/**
	 * 
	 * @param iter the histogram id iterator
	 * @throws SQLException if there is a problem deleting vectors
	 */
	private void deleteVectors(Iterator<IdHistogram> iter) throws SQLException {
		while (iter.hasNext()) {
			IdHistogram hist = iter.next();
			deleteVectors(hist.id, hist.count);
		}
	}

	/**
	 * Low level count decrement of a vector record from vectable, if count
	 * reaches zero, the record is deleted
	 * @param id vector row ID
	 * @param countdiff the amount to subtract from count
	 * @return 0 if decrement short of 0, return 1 if record was removed, return
	 *         -1 if there was a problem
	 * @throws SQLException if there is a problem creating or executing the query
	 */
	protected abstract int deleteVectors(long id, int countdiff) throws SQLException;

	long recoverExternalFunctionId(String exename, String functionname, String reparch)
			throws SQLException, LSHException {
		String md5 = ExecutableRecord.calcLibraryMd5Placeholder(exename, reparch);
		ExecutableRow row = exeTable.queryMd5ExeMatch(md5);
		if (row == null) {
			throw new LSHException("Could not resolve filter specifying executable: " + exename);
		}

		DescriptionRow descRow = descTable.queryFuncNameAddr(row.rowid, functionname, -1);
		if (descRow == null) {
			throw new LSHException(
				"Could not resolve filter specifying function: [" + exename + "]" + functionname);
		}
		return descRow.rowid;
	}

	// Pulled-in from old FunctionDatabaseClient

	/**
	 * Make sure the FunctionDescription has its attached SignatureRecord, if not, query for it
	 * @param functionDescription is the FunctionDescription
	 * @param descriptionManager is the container
	 * @param sigmap is a container of cached SignatureRecords which is checked before querying (may be null)
	 * @throws SQLException if there is a problem querying the vector ID
	 */
	private void queryAssociatedSignature(FunctionDescription functionDescription,
			DescriptionManager descriptionManager, Map<Long, SignatureRecord> sigmap)
			throws SQLException {
		if (functionDescription.getSignatureRecord() != null) {
			return;
		}
		long vectorId = functionDescription.getVectorId();
		if (vectorId == 0) {
			return;		// We don't know the id
		}
		VectorResult rowres;
		SignatureRecord srec;
		if (sigmap != null) {
			srec = sigmap.get(vectorId);
			if (srec == null) {
				rowres = queryVectorId(vectorId);
				srec = descriptionManager.newSignature(rowres.vec, rowres.hitcount);
				descriptionManager.setSignatureId(srec, vectorId);
				sigmap.put(vectorId, srec);
			}
		}
		else {
			rowres = queryVectorId(vectorId);
			srec = descriptionManager.newSignature(rowres.vec, rowres.hitcount);
			descriptionManager.setSignatureId(srec, vectorId);
		}
		descriptionManager.attachSignature(functionDescription, srec);
	}

	/**
	 * 
	 * @param id the vector id
	 * @return the vector result 
	 * @throws SQLException if there is a problem creating or executing the query
	 */
	protected abstract VectorResult queryVectorId(long id) throws SQLException;

	/**
	 * Make sure every FunctionDescription object has its associated SignatureRecord
	 * Read the SignatureRecords from the database if necessary
	 * 
	 * @param funcvec list of functions
	 * @param manager container DescriptionManager
	 * @throws SQLException if there is a problem querying the signature
	 */
	private void queryAssociatedSignatures(List<FunctionDescription> funcvec,
			DescriptionManager manager) throws SQLException {
		TreeMap<Long, SignatureRecord> sigmap = new TreeMap<>();
		for (FunctionDescription element : funcvec) {
			queryAssociatedSignature(element, manager, sigmap);
		}
	}

	/**
	 * Returns the total number of hits in the given result set.
	 * 
	 * @param resultSet the list of vector results
	 * @return the number of hits
	 */
	private int getTotalCount(List<VectorResult> resultSet) {
		int count = 0;
		for (VectorResult res : resultSet) {
			count += res.hitcount;
		}
		return count;
	}

	/**
	 * This is an internal function for the -insert- capability
	 * It runs through executables in -input- and tests if similar records are already present
	 * If an executable existed in the database previously:
	 * <ul>
	 *   <li>if the executable is NOT a library it throws DatabaseNonFatalException to indicate this file is already ingested
	 *   <li>if the executable is a library then
	 *   <ul>
	 *      <li>it runs through all functions associated with the library
	 *      <li>if there is already a record for the function it marks the object in -input- so
	 *      that a duplicate won't get entered for that function.
	 *   </ul>
	 * </ul>
	 * @param input is the DescriptionManager
	 * @throws LSHException if this executable has already been inserted
	 * @throws SQLException if there is an error issuing the query
	 * @throws DatabaseNonFatalException if a library has already been ingested (non-fatal)
	 */
	private void testExecutableDuplication(DescriptionManager input)
			throws SQLException, LSHException, DatabaseNonFatalException {
		boolean pickout_storedfuncs = false;
		for (ExecutableRecord erec : input.getExecutableRecordSet()) {
			ExecutableRow row = exeTable.queryMd5ExeMatch(erec.getMd5());
			if (row != null) { // Already have a matching executable
				ExecutableRecord tmp = makeExecutableRecordTemp(row);
				int cmp = tmp.compareMetadata(erec);
				if (cmp != 0) {
					String fatalerror = FunctionDatabase.constructFatalError(cmp, erec, tmp);
					if (fatalerror != null) {
						throw new LSHException(fatalerror);
					}
					throw new DatabaseNonFatalException(
						FunctionDatabase.constructNonfatalError(cmp, erec, tmp));
				}
				if (erec.getRowId() != null) {
					if (!erec.getRowId().equals(tmp.getRowId())) {
						throw new LSHException(
							"Id mismatch when inserting executable: " + erec.getNameExec());
					}
				}
				else {
					input.setExeRowId(erec, tmp.getRowId());
				}
				input.setExeAlreadyStored(erec);
				// Just because we've seen a library before doesn't mean we should stop function insertion
				// Libraries are likely to be partially inserted multiple times
				if (!erec.isLibrary()) {
					throw new DatabaseNonFatalException(
						erec.getNameExec() + " is already ingested");
				}
				pickout_storedfuncs = true; // At least one executable has previously inserted functions
			}
		}

		if (pickout_storedfuncs) {
			if (!markPreviouslyStoredFunctions(input, input.listAllFunctions())) {
				throw new DatabaseNonFatalException("Already inserted");
			}
		}
	}

	/**
	 * Do the final work of inserting new ExecutableRecords into the database. This function
	 * assumes testExecutableDuplication has already run and marked previously ingested records
	 * 
	 * @param input the executable descriptor
	 * @throws SQLException if database records cannot be inserted
	 */
	private void commitExecutables(DescriptionManager input) throws SQLException {
		Iterator<ExecutableRecord> iter = input.getExecutableRecordSet().iterator();
		while (iter.hasNext()) {
			ExecutableRecord erec = iter.next();
			if (erec.isAlreadyStored()) {
				continue;
			}
			long newid = exeTable.insert(erec);
			input.setExeRowId(erec, new RowKeySQL(newid));
		}
		if (info.execats != null) {
			iter = input.getExecutableRecordSet().iterator();
			while (iter.hasNext()) {
				ExecutableRecord erec = iter.next();
				exeCategoryTable.storeExecutableCategories(erec);
			}
		}
	}

	@Override
	public Status getStatus() {
		if (status == Status.Unconnected) {
			// defer to data source for connection pool status
			return ds.getStatus();
		}
		return status;
	}

	@Override
	public ConnectionType getConnectionType() {
		return ds.getConnectionType();
	}

	@Override
	public String getUserName() {
		return null;
	}

	@Override
	public void setUserName(String userName) {
		// ignore
	}

	@Override
	public LSHVectorFactory getLSHVectorFactory() {
		return vectorFactory;
	}

	@Override
	public DatabaseInformation getInfo() {
		return info;
	}

	@Override
	public int compareLayout() {
		// version ignored if supportedLayoutVersion < 0
		if (supportedLayoutVersion < 0 || info.layout_version == supportedLayoutVersion) {
			return 0;
		}
		return (info.layout_version < supportedLayoutVersion) ? -1 : 1;
	}

	@Override
	public BSimServerInfo getServerInfo() {
		return ds.getServerInfo();
	}

	@Override
	public String getURLString() {
		return ds.getServerInfo().toURLString();
	}

	@Override
	public Error getLastError() {
		return lasterror;
	}

	/**
	 * Create a new database
	 * 
	 * @param config is the configuration information for the database
	 * @throws SQLException if a database connection cannot be established
	 */
	private void generate(Configuration config) throws SQLException {
		config.info.layout_version = supportedLayoutVersion;
		info = config.info;
		vectorFactory.set(config.weightfactory, config.idflookup, config.info.settings);

		createDatabase(config);
		status = Status.Ready;
		isinit = true;
	}

	@Override
	public boolean initialize() {
		if (isinit) {
			return true;
		}
		try {
			Configuration config = new Configuration();
			initializeDatabase(config);
			info = config.info;
			vectorFactory.set(config.weightfactory, config.idflookup, config.info.settings);
		}
		catch (CancelledSQLException e) {
			status = Status.Error;
			lasterror = new Error(ErrorCategory.AuthenticationCancelled,
				"Authentication cancelled by user");
			return false;
		}
		catch (SQLException err) {
			status = Status.Error;
			// Pooled connections add an additional wrapper
			Throwable cause = err.getCause();
			if (cause == null) {
				cause = err;
			}
			String msg = cause.getMessage();
			if (msg.contains("already in use:")) {
				lasterror = new Error(ErrorCategory.Initialization,
					"Database already in use by another process");
			}
			else if (msg.contains("authentication failed") ||
				msg.contains("requires a valid client certificate")) {
				lasterror =
					new Error(ErrorCategory.Authentication, "Could not authenticate with database");
			}
			else if (msg.contains("does not exist") && !msg.contains(" role ")) {
				lasterror = new Error(ErrorCategory.Nodatabase, cause.getMessage());
			}
			else {
				lasterror = new Error(ErrorCategory.Initialization,
					"Database error on initialization: " + cause.getMessage());
			}
			return false;
		}
//		catch (NoDatabaseException err) {
//			info = null;
//			lasterror = new Error(ErrorCategory.Nodatabase,
//				"Database has not been created yet: " + err.getMessage());
//
//			isinit = true;
//			status = Status.Ready;
//			return true;
//		}

		status = Status.Ready;
		isinit = true;
		return true;
	}

	/**
	 * Insert a set of (possible callgraph interrelated) functions into database,
	 * @param input is the DescriptionManager container of the functions and executables
	 * 
	 * @throws LSHException if there are duplicate executables
	 * @throws SQLException if there is an error issuing the query
	 * @throws DatabaseNonFatalException if there are duplicate executables
	 */
	private void insert(DescriptionManager input)
			throws SQLException, LSHException, DatabaseNonFatalException {

		beginTransaction(true);
		boolean commit = false;
		try {
			testExecutableDuplication(input);
			commitExecutables(input);
			Iterator<FunctionDescription> iter = input.listAllFunctions();
			long start_id = 0;
			while (iter.hasNext()) {
				FunctionDescription func = iter.next();
				if (func.getId() != null) {
					continue; // Already inserted
				}
				SignatureRecord srec = func.getSignatureRecord();
				if (srec != null) {
					long sig_id = storeSignatureRecord(srec);
					input.setSignatureId(srec, sig_id);
				}
				long id = descTable.insert(func);
				if (start_id == 0) {
					start_id = id;
				}
				input.setFunctionDescriptionId(func, new RowKeySQL(id));
			}
			if (trackcallgraph) {
				iter = input.listAllFunctions();
				while (iter.hasNext()) {
					FunctionDescription func = iter.next();
					if (func.getId().getLong() < start_id) {
						continue; // Already inserted
					}
					callgraphTable.insert(func);
				}
			}
			commit = true;
		}
		finally {
			endTransaction(commit);
		}
	}

	/**
	 * Make sure the vector corresponding to the SignatureRecord is inserted into the vectable
	 * @param sigrec is the SignatureRecord
	 * @return the computed id of the vector
	 * @throws SQLException if there is a problem creating or executing the query
	 */
	protected abstract long storeSignatureRecord(SignatureRecord sigrec) throws SQLException;

	/**
	 * Query the database for functions with a similar feature vector to -vec-
	 * @param simres receives the list of results and their similarity to the base vector
	 * @param res is the DescriptionManager container for the results
	 * @param vec is the feature vector to match
	 * @param query contains various thresholds for the query
	 * @param filter specifies additional conditions functions (and exes) must meet after meeting sim/signif threshold
	 * @param vecToResultsMap list of result vectors
	 * @throws SQLException if there is an error issuing the query 
	 * @throws LSHException if executable record creation fails
	 */
	private void queryNearest(SimilarityResult simres, DescriptionManager res, LSHVector vec,
			QueryNearest query, BSimSqlClause filter,
			HashMap<LSHVector, List<VectorResult>> vecToResultsMap)
			throws SQLException, LSHException {
		List<VectorResult> resultset = new ArrayList<>();
		int vectormax = query.vectormax;
		if (vectormax == 0) {
			vectormax = 2000000; // Really means a very big limit
		}

		// Check to see if we've already queried for this vector before. If so, just grab
		// the results from the map.
		if (vecToResultsMap.containsKey(vec)) {
			resultset = vecToResultsMap.get(vec);
			simres.setTotalCount(getTotalCount(resultset));
		}
		else {
			// Perform the query.
			simres.setTotalCount(
				queryNearestVector(resultset, vec, query.thresh, query.signifthresh, vectormax));

			// Put the new results in the map so we can use them if another 
			// similar vector comes along.
			vecToResultsMap.put(vec, resultset);
		}

		int count = 0;

		for (VectorResult dresult : resultset) {
			if (count >= query.max) {
				break;
			}
			count += retrieveFuncDescFromVectors(dresult, res, count, query, filter, simres);
		}
	}

	/**
	 * Generates {@link FunctionDescription} objects for each function with signature vector
	 * {@code dresult}.  If a non-null {@code filter} is provided, {@link FunctionDescription}s
	 * are only created for functions with pass the filter.
	 * 
	 * @param dresult {@link VectorResult} representing a matching vector
	 * @param res {@link DescriptionManager} container for the results
	 * @param count number of function descriptions which have already been returned for this base 
	 *          vector
	 * @param query contains various thresholds for the query
	 * @param filter specifies additional conditions functions (and exes) must meet after 
	 *          meeting sim/signif threshold
	 * @param simres receives the list of results and their similarity to the base vector
	 * @return number of 
	 * @throws SQLException if there is an error issuing the query
	 * @throws LSHException if executable record creation fails
	 */
	protected int retrieveFuncDescFromVectors(VectorResult dresult, DescriptionManager res,
			int count, QueryNearest query, BSimSqlClause filter, SimilarityResult simres)
			throws SQLException, LSHException {
		SignatureRecord srec = res.newSignature(dresult.vec, dresult.hitcount);
		List<DescriptionRow> descres;
		if (filter == null) {
			descres = descTable.queryVectorIdMatch(dresult.vectorid, query.max - count);
		}
		else {
			descres = descTable.queryVectorIdMatchFilter(dresult.vectorid, filter.tableClause(),
				filter.whereClause(), query.max - count);
		}
		if (descres == null) {
			throw new SQLException("Error querying vectorid: " + Long.toString(dresult.vectorid));
		}
		if (descres.size() == 0) {
			if (filter != null) {
				return 0; // Filter may have eliminated all results
			}
			// Otherwise this is a sign of corruption in the database
			throw new SQLException(
				"No functions matching vectorid: " + Long.toString(dresult.vectorid));
		}
		convertDescriptionRows(simres, descres, dresult, res, srec);
		return descres.size();
	}

	/**
	 * 
	 * @param resultset the list of result set objects to populate
	 * @param vec the vector containing the saveSQL query statement
	 * @param simthresh the similarity threshold
	 * @param sigthresh the confidence threshold
	 * @param max the max number of results to return
	 * @return the number of results returned
	 * @throws SQLException if there is a problem creating or executing the query
	 */
	protected abstract int queryNearestVector(List<VectorResult> resultset, LSHVector vec,
			double simthresh, double sigthresh, int max) throws SQLException;

	/**
	 * Perform nearest vector query based upon specified query which contains response
	 * record which should be filled-in with search results.
	 * 
	 * @param query the nearest vector query to perform
	 * @throws SQLException if there is an error issuing the query
	 */
	protected abstract void queryNearestVector(QueryNearestVector query) throws SQLException;

	/**
	 * Query for function names within a previously queried executable -erec-
	 * 
	 * @param functionDescriptions list of functions to be filled in by the query (may be null)
	 * @param manager container for record
	 * @param executableRecord previously queried ExecutableRecord
	 * @param functionName name to query for, if empty string, all functions in executable are returned
	 * @param shouldReturnSignatures true if signature of queried functions should also be returned
	 * @param maxResults maximum results to return
	 * @throws SQLException if there is an error issuing the query
	 */
	private void queryByName(List<FunctionDescription> functionDescriptions,
			DescriptionManager manager, ExecutableRecord executableRecord, String functionName,
			boolean shouldReturnSignatures, int maxResults) throws SQLException {
		if (functionDescriptions == null) {
			functionDescriptions = new ArrayList<>();
		}
		if (functionName.length() == 0) {
			queryAllFunc(functionDescriptions, executableRecord, manager, maxResults);
		}
		else {
			List<DescriptionRow> descres = descTable
					.queryFuncName(executableRecord.getRowId().getLong(), functionName, maxResults);
			descTable.convertDescriptionRows(functionDescriptions, descres, executableRecord,
				manager, null);
		}
		if (shouldReturnSignatures) {
			queryAssociatedSignatures(functionDescriptions, manager);
		}
	}

	/**
	 * Query for single function by name and address, within an executable
	 * @param manager - container for record
	 * @param erec - previously queried ExecutableRecord
	 * @param funcname - name of function to query for
	 * @param address - address of function to query for
	 * @param sigs - true if signature of function should also be returned
	 * @return the resulting FunctionDescription or null
	 * @throws SQLException if there is an error issuing the query
	 */
	private FunctionDescription queryByNameAddress(DescriptionManager manager,
			ExecutableRecord erec, String funcname, long address, boolean sigs)
			throws SQLException {
		DescriptionRow row =
			descTable.queryFuncNameAddr(erec.getRowId().getLong(), funcname, address);
		FunctionDescription func = DescriptionTable.convertDescriptionRow(row, erec, manager, null);
		if (sigs) {
			queryAssociatedSignature(func, manager, null);
		}
		return func;
	}

	/**
	 * Returns a list of all executables in the repository. 
	 * 
	 * @param manager the description manager
	 * @param limit the max number of results to return
	 * @param filterMd5 md5 filter
	 * @param filterExeName executable name filter
	 * @param filterArch architecture filter
	 * @param filterCompilerName compiler name filter
	 * @param columnName the primary sort column name
	 * @param includeFakes if false, will exclude generated MD5s starting with "bbbbbbbbaaaaaaaa"
	 * @return list of executables in the repository
	 * @throws SQLException when issuing the SQL query
	 * @throws LSHException when creating the executable record
	 */
	private List<ExecutableRecord> queryExecutables(DescriptionManager manager, int limit,
			String filterMd5, String filterExeName, long filterArch, long filterCompilerName,
			ExeTableOrderColumn columnName, boolean includeFakes)
			throws SQLException, LSHException {

		List<ExecutableRecord> records = new ArrayList<>();

		List<ExecutableRow> rows = exeTable.queryAllExe(limit, filterMd5, filterExeName, filterArch,
			filterCompilerName, columnName, includeFakes);

		for (ExecutableRow row : rows) {
			ExecutableRecord record = exeTable.makeExecutableRecord(manager, row);
			records.add(record);
		}
		return records;
	}

	private ExecutableRecord findSingleExecutable(ExeSpecifier spec, DescriptionManager manager)
			throws SQLException, LSHException {
		if (!StringUtils.isBlank(spec.exemd5)) {
			ExecutableRow row = exeTable.queryMd5ExeMatch(spec.exemd5);
			if (row == null) {
				return null;
			}
			return exeTable.makeExecutableRecord(manager, row);
		}
		if (StringUtils.isBlank(spec.exename)) {
			throw new LSHException("ExeSpecifier must provide either md5 or name");
		}
		return exeTable.querySingleExecutable(manager, spec.exename, spec.arch, spec.execompname);
	}

	private ExecutableRecord findSingleExeWithMap(ExeSpecifier exe, DescriptionManager manager,
			TreeMap<ExeSpecifier, ExecutableRecord> nameMap) throws SQLException, LSHException {
		ExecutableRecord erec = nameMap.get(exe);
		if (erec != null) {
			return erec;
		}
		erec = findSingleExecutable(exe, manager);
		nameMap.put(exe, erec);			// Cache ExecutableRecord in map, even if its null
		return erec;
	}

	/**
	 * Query for an executable via its md5 hash
	 * @param md5 is the 32-character md5 hash
	 * @param res is DescriptionManager container to hold the result
	 * @return the ExecutableRecord is it was found, null otherwise
	 * @throws LSHException if executable record creation fails
	 * @throws SQLException if there is an error issuing the query
	 */
	private ExecutableRecord queryExecutableByMd5(String md5, DescriptionManager res)
			throws LSHException, SQLException {
		ExecutableRow row = exeTable.queryMd5ExeMatch(md5);
		if (row != null) {
			return exeTable.makeExecutableRecord(res, row);
		}
		return null;
	}

	/**
	 * For every function currently in the manager, fill in its call graph information
	 * @param manage the executable descriptor
	 * @throws LSHException if the database does not track call graph information
	 * @throws SQLException if there is a problem querying for function information
	 */
	private void queryCallgraph(DescriptionManager manage) throws LSHException, SQLException {
		if (!info.trackcallgraph) {
			throw new LSHException("Database does not track callgraph");
		}
		TreeMap<RowKey, FunctionDescription> funcmap = new TreeMap<>();
		manage.generateFunctionIdMap(funcmap);
		List<FunctionDescription> funclist = new ArrayList<>();
		for (FunctionDescription element : funcmap.values()) { // Build a static copy of the list of functions
			funclist.add(element);
		}
		for (FunctionDescription element : funclist) {
			fillinChildren(element, manage, funcmap);
		}
	}

	protected QueryResponseRecord doQuery(BSimQuery<?> query, Connection c)
			throws LSHException, SQLException, DatabaseNonFatalException {
		if (query instanceof QueryNearest q) {
			fdbQueryNearest(q);
		}
		else if (query instanceof QueryNearestVector q) {
			fdbQueryNearestVector(q);
		}
		else if (query instanceof InsertRequest q) {
			fdbDatabaseInsert(q);
		}
		else if (query instanceof QueryInfo q) {
			fdbDatabaseInfo(q);
		}
		else if (query instanceof QueryName q) {
			fdbQueryName(q);
		}
		else if (query instanceof QueryExeInfo q) {
			fdbQueryExeInfo(q);
		}
		else if (query instanceof QueryExeCount q) {
			fdbQueryExeCount(q);
		}
		else if (query instanceof CreateDatabase q) {
			fdbDatabaseCreate(q);
		}
		else if (query instanceof QueryChildren q) {
			fdbQueryChildren(q);
		}
		else if (query instanceof QueryDelete q) {
			fdbDelete(q);
		}
		else if (query instanceof QueryUpdate q) {
			fdbUpdate(q);
		}
		else if (query instanceof QueryVectorId q) {
			fdbQueryVectorId(q);
		}
		else if (query instanceof QueryVectorMatch q) {
			fdbQueryVectorMatch(q);
		}
		else if (query instanceof QueryPair q) {
			fdbQueryPair(q);
		}
		else if (query instanceof QueryOptionalValues q) {
			fdbQueryOptionalValues(q);
		}
		else if (query instanceof InsertOptionalValues q) {
			fdbInsertOptionalValues(q);
		}
		else if (query instanceof QueryOptionalExist q) {
			fdbOptionalExist(q);
		}
		else if (query instanceof InstallCategoryRequest q) {
			fdbInstallCategory(q);
		}
		else if (query instanceof InstallTagRequest q) {
			fdbInstallTag(q);
		}
		else if (query instanceof InstallMetadataRequest q) {
			fdbInstallMetadata(q);
		}
		else {
			return null;
		}
		return query.getResponse();
	}

	@Override
	public QueryResponseRecord query(BSimQuery<?> query) {

		lasterror = null;
		try {
			if (!(query instanceof CreateDatabase) && !initialize()) {
				lasterror = new Error(ErrorCategory.Nodatabase, "The database does not exist");
				return null;
			}

			query.buildResponseTemplate();
			QueryResponseRecord response = doQuery(query, db);
			if (response == null) {
				lasterror = new Error(ErrorCategory.Fatal, "Unknown query type");
				query.clearResponse();
			}
		}
		catch (DatabaseNonFatalException err) {
			lasterror = new Error(ErrorCategory.Nonfatal,
				"Skipping -" + query.getName() + "- : " + err.getMessage());
			query.clearResponse();
		}
		catch (LSHException err) {
			lasterror = new Error(ErrorCategory.Fatal,
				"Fatal error during -" + query.getName() + "- : " + err.getMessage());
			query.clearResponse();
		}
		catch (SQLException err) {
			lasterror = new Error(ErrorCategory.Fatal,
				"SQL error during -" + query.getName() + "- : " + err.getMessage());
			query.clearResponse();
		}
		return query.getResponse();
	}

	/**
	 * Entry point for the QueryNearestVector command
	 * 
	 * @param query the query to execute
	 * @throws LSHException if the provided signature data is invalid
	 * @throws SQLException if there is an error issuing the query
	 */
	private void fdbQueryNearestVector(QueryNearestVector query) throws LSHException, SQLException {
		FunctionDatabase.checkSettingsForQuery(query.manage, info);
		queryNearestVector(query);
	}

	/**
	 * Entry point for the QueryPair command
	 * 
	 * @param query the query to execute
	 * @throws SQLException if there is an error issuing the query
	 * @throws LSHException if no md5 or exe name is provided
	 */
	private void fdbQueryPair(QueryPair query) throws SQLException, LSHException {
		ResponsePair response = query.pairResponse;
		ResponsePair.Accumulator accumulator = new ResponsePair.Accumulator();

		List<FunctionDescription> aFuncList = new ArrayList<>();
		List<FunctionDescription> bFuncList = new ArrayList<>();
		DescriptionManager resManage = new DescriptionManager();
		TreeMap<ExeSpecifier, ExecutableRecord> nameMap = new TreeMap<>();
		for (PairInput pairInput : query.pairs) {
			FunctionDescription funcA = null;
			FunctionDescription funcB = null;
			ExecutableRecord erec = findSingleExeWithMap(pairInput.execA, resManage, nameMap);
			if (erec == null) {
				accumulator.missedExe += 1;
			}
			else {
				funcA = queryByNameAddress(resManage, erec, pairInput.funcA.funcName,
					pairInput.funcA.address, true);
				if (funcA == null) {
					accumulator.missedFunc += 1;
				}
			}

			erec = findSingleExeWithMap(pairInput.execB, resManage, nameMap);
			if (erec == null) {
				accumulator.missedExe += 1;
			}
			else {
				funcB = queryByNameAddress(resManage, erec, pairInput.funcB.funcName,
					pairInput.funcB.address, true);
				if (funcB == null) {
					accumulator.missedFunc += 1;
				}
			}
			aFuncList.add(funcA);
			bFuncList.add(funcB);
		}

		Iterator<FunctionDescription> bIter = bFuncList.iterator();
		VectorCompare vectorData = new VectorCompare();
		for (FunctionDescription funcA : aFuncList) {
			FunctionDescription funcB = bIter.next();
			if (funcA == null || funcB == null) {
				continue;
			}
			SignatureRecord sigA = funcA.getSignatureRecord();
			if (sigA == null) {
				accumulator.missedVector += 1;
				continue;
			}
			SignatureRecord sigB = funcB.getSignatureRecord();
			if (sigB == null) {
				accumulator.missedVector += 1;
				continue;
			}
			double sim = sigA.getLSHVector().compare(sigB.getLSHVector(), vectorData);
			double signif = vectorFactory.calculateSignificance(vectorData);
			PairNote pairNote = new PairNote(funcA, funcB, sim, signif, vectorData.dotproduct,
				vectorData.acount, vectorData.bcount, vectorData.intersectcount);
			response.notes.add(pairNote);
			accumulator.pairCount += 1;
			accumulator.sumSim += sim;
			accumulator.sumSimSquare += sim * sim;
			accumulator.sumSig += signif;
			accumulator.sumSigSquare += signif * signif;
		}
		response.scale = vectorFactory.getSignificanceScale();
		response.fillOutStatistics(accumulator);
	}

	/**
	 * Entry point for the QueryNearest command
	 * 
	 * @param query the query to execute
	 * @throws LSHException if there is a problem creating executable records
	 * @throws SQLException if there is an error issuing the query
	 */
	private void fdbQueryNearest(QueryNearest query) throws LSHException, SQLException {
		FunctionDatabase.checkSettingsForQuery(query.manage, info);
		BSimSqlClause filter = null;
		if (query.bsimFilter != null) {
			ExecutableRecord repexe = query.manage.getExecutableRecordSet().first();
			IDSQLResolution idres[] = new IDSQLResolution[query.bsimFilter.numAtoms()];
			for (int i = 0; i < idres.length; ++i) {
				FilterAtom atom = query.bsimFilter.getAtom(i);
				idres[i] = atom.type.generateIDSQLResolution(atom);
				if (idres[i] != null) {
					idres[i].resolve(this, repexe);
				}
			}
			filter = SQLEffects.createFilter(query.bsimFilter, idres, this);
		}
		ResponseNearest response = query.nearresponse;
		response.totalfunc = 0;
		response.totalmatch = 0;
		response.uniquematch = 0;

		DescriptionManager descMgr = new DescriptionManager();
		Iterator<FunctionDescription> iter = query.manage.listAllFunctions();

		queryFunctions(query, filter, response, descMgr, iter);
		response.manage.transferSettings(query.manage); // Echo back the
														// settings
		if (query.fillinCategories && (info.execats != null)) {
			fillinExecutableCategories(response.manage);
		}
	}

	/**
	 * Entry point for the QueryVectorId command
	 * 
	 * @param query contains list of ids to query
	 * @throws SQLException if there is an error issuing the query
	 */
	private void fdbQueryVectorId(QueryVectorId query) throws SQLException {
		for (Long id : query.vectorIds) {
			VectorResult res = queryVectorId(id);
			query.vectorIdResponse.vectorResults.add(res);
		}
	}

	/**
	 * Entry point for the QueryVectorMatch command
	 * 
	 * @param query contains list of ids to match
	 * @throws SQLException if there is an error issuing the query
	 * @throws LSHException if there is a problem making executable records
	 */
	private void fdbQueryVectorMatch(QueryVectorMatch query) throws SQLException, LSHException {
		BSimSqlClause filter = null;
		if (query.bsimFilter != null) {
			ExecutableRecord repexe = null;		// Needed for the ExternalFunction filter
			IDSQLResolution idres[] = new IDSQLResolution[query.bsimFilter.numAtoms()];
			for (int i = 0; i < idres.length; ++i) {
				FilterAtom atom = query.bsimFilter.getAtom(i);
				idres[i] = atom.type.generateIDSQLResolution(atom);
				if (idres[i] != null) {
					idres[i].resolve(this, repexe);
				}
			}
			filter = SQLEffects.createFilter(query.bsimFilter, idres, this);
		}
		List<VectorResult> vectorList = new ArrayList<>();
		for (Long id : query.vectorIds) {
			VectorResult vecResult = queryVectorId(id);
			vectorList.add(vecResult);
		}
		int count = 0;
		DescriptionManager manage = query.matchresponse.manage;
		for (VectorResult vecResult : vectorList) {
			if (count >= query.max) {
				break;
			}
			SignatureRecord srec = manage.newSignature(vecResult.vec, vecResult.hitcount);
			List<DescriptionRow> descres;
			if (filter == null) {
				descres = descTable.queryVectorIdMatch(vecResult.vectorid, query.max - count);
			}
			else {
				descres = descTable.queryVectorIdMatchFilter(vecResult.vectorid,
					filter.tableClause(), filter.whereClause(), query.max - count);
			}
			if (descres == null) {
				throw new SQLException(
					"Error querying vectorid: " + Long.toString(vecResult.vectorid));
			}
			if (descres.size() == 0) {
				if (filter != null) {
					continue; // Filter may have eliminated all results
				}
				// Otherwise this is a sign of corruption in the database
				throw new SQLException(
					"No functions matching vectorid: " + Long.toString(vecResult.vectorid));
			}
			count += descres.size();
			convertDescriptionRows(null, descres, vecResult, manage, srec);
		}
		if (query.fillinCategories && (info.execats != null)) {
			fillinExecutableCategories(manage);
		}
	}

	/**
	 * @param query the query to execute
	 * @param filter the function filter 
	 * @param response the response object
	 * @param descMgr the executable descriptor 
	 * @param iter the function iterator 
	 * @return the number of unique results found
	 * @throws SQLException if there is an error issuing the query
	 * @throws LSHException if there is a problem creating executable records
	 */
	protected int queryFunctions(QueryNearest query, BSimSqlClause filter, ResponseNearest response,
			DescriptionManager descMgr, Iterator<FunctionDescription> iter)
			throws SQLException, LSHException {

		// Keep a map of the feature vectors and their query results; if we have vectors that
		// are of equal value, we'll just query the first one, and use those results for the
		// others.
		HashMap<LSHVector, List<VectorResult>> vecToResultMap = new HashMap<>();

		while (iter.hasNext()) {
			FunctionDescription frec = iter.next();
			SignatureRecord srec = frec.getSignatureRecord();

			if (srec == null) {
				continue;
			}
			LSHVector thevec = srec.getLSHVector();
			double len2 = vectorFactory.getSelfSignificance(thevec);

			// Self significance should be bigger than the significance threshold
			// (or its impossible our result can exceed the threshold)
			if (len2 < query.signifthresh) {
				continue;
			}
			response.totalfunc += 1;
			SimilarityResult simres = new SimilarityResult(frec);
			if (descMgr.getExecutableRecordSet().size() > 1000) {
				descMgr.clear();
			}
			else {
				// Try to preserve ExecutableRecords so we don't have to do SQL 
				// every time
				descMgr.clearFunctions();
			}
			queryNearest(simres, descMgr, thevec, query, filter, vecToResultMap);
			if (simres.size() == 0) {
				continue;
			}
			response.totalmatch += 1;
			if (simres.size() == 1) {
				response.uniquematch += 1;
			}

			response.result.add(simres);

			simres.transfer(response.manage, true);
		}

		return vecToResultMap.size();
	}

	/**
	 * Entry point for the InsertRequest command
	 * @param query the query to execute
	 * @throws LSHException if trying to insert into a read-only database
	 * @throws SQLException if there is an error issuing the query
	 * @throws DatabaseNonFatalException if there are duplicate executables and/or functions
	 */
	private void fdbDatabaseInsert(InsertRequest query)
			throws LSHException, SQLException, DatabaseNonFatalException {
		if (info.readonly) {
			throw new LSHException("Trying to insert on read-only database");
		}
		if (FunctionDatabase.checkSettingsForInsert(query.manage, info)) { // Check if settings are valid and is this is first insert
			info.major = query.manage.getMajorVersion();
			info.minor = query.manage.getMinorVersion();
			info.settings = query.manage.getSettings();
			keyValueTable.writeBasicInfo(info); // Save off the settings associated with this first insert
		}
		ResponseInsert response = query.insertresponse;
		if ((query.repo_override != null) && (query.repo_override.length() != 0)) {
			query.manage.overrideRepository(query.repo_override, query.path_override);
		}
		insert(query.manage);
		response.numexe = query.manage.getExecutableRecordSet().size();
		response.numfunc = query.manage.numFunctions();
	}

	/**
	 * Entry point for the QueryInfo command
	 * @param query the query to execute
	 */
	private void fdbDatabaseInfo(QueryInfo query) {
		ResponseInfo response = query.inforesponse;
		response.info = info;
	}

	/**
	 * Entry point for the QueryName command
	 * @param query the query to execute
	 * @throws SQLException if there is an error issuing the query
	 * @throws LSHException if there is a problem query callgraph informatino
	 */
	private void fdbQueryName(QueryName query) throws SQLException, LSHException {
		ResponseName response = query.nameresponse;
		response.printselfsig = query.printselfsig;
		response.printjustexe = query.printjustexe;
		response.manage.setVersion(info.major, info.minor);
		response.manage.setSettings(info.settings);

		ExecutableRecord erec = findSingleExecutable(query.spec, response.manage);
		if (erec == null) {
			response.uniqueexecutable = false;
			return;
		}
		response.uniqueexecutable = true;

		queryByName(null, response.manage, erec, query.funcname, query.fillinSigs, query.maxfunc);
		if (query.fillinCallgraph) {
			queryCallgraph(response.manage);
		}
		if (query.fillinCategories && (info.execats != null)) {
			fillinExecutableCategories(response.manage);
		}
	}

	/**
	 * Queries the database for all executables matching the search criteria in the given
	 * {@link QueryExeInfo} object. Results are stored in the query info object
	 * 
	 * @param query the query information
	 * @throws SQLException if there is an error executing the query
	 * @throws LSHException if there is an error executing the query
	 */
	private void fdbQueryExeInfo(QueryExeInfo query) throws SQLException, LSHException {
		ResponseExe response = query.exeresponse;

		boolean unknownArchOrCompiler = false;

		long archId = 0;
		if (query.filterArch != null) {
			archId = queryArchString(query.filterArch);
			if (archId == 0) {
				unknownArchOrCompiler = true;
				Msg.warn(this,
					"Architecture ID not defined within BSim database: " + query.filterArch);
			}
		}

		long compId = 0;
		if (query.filterCompilerName != null) {
			compId = queryCompilerString(query.filterCompilerName);
			if (compId == 0) {
				unknownArchOrCompiler = true;
				Msg.warn(this,
					"Compiler ID not defined within BSim database: " + query.filterCompilerName);
			}
		}

		if (unknownArchOrCompiler) {
			response.records = List.of();
			response.recordCount = 0;
			return;
		}

		List<ExecutableRecord> records =
			queryExecutables(response.manage, query.limit, query.filterMd5, query.filterExeName,
				archId, compId, query.sortColumn, query.includeFakes);
		response.records = records;
		response.recordCount = records.size();
		if (query.fillinCategories && (info.execats != null)) {
			fillinExecutableCategories(response.manage);
		}
	}

	/**
	 * Queries the database for the number of executables matching the filter criteria
	 * 
	 * @param query the query information
	 * @throws SQLException if there is an error executing the query
	 */
	private void fdbQueryExeCount(QueryExeCount query) throws SQLException {
		ResponseExe response = query.exeresponse;
		long archId = 0;
		if (query.filterArch != null) {
			archId = queryArchString(query.filterArch);
		}
		long compId = 0;
		if (query.filterCompilerName != null) {
			compId = queryCompilerString(query.filterCompilerName);
		}
		response.recordCount = exeTable.queryExeCount(query.filterMd5, query.filterExeName, archId,
			compId, query.includeFakes);
	}

	/**
	 * Entry point for the QueryChildren command
	 * @param query the query to execute
	 * @throws LSHException if the database does not track callgraph or the function is not found
	 * @throws SQLException if there is an error issuing the query
	 */
	private void fdbQueryChildren(QueryChildren query) throws LSHException, SQLException {
		if (!info.trackcallgraph) {
			throw new LSHException("Database does not track callgraph");
		}
		ResponseChildren response = query.childrenresponse;
		ExecutableRecord exe = null;

		if (query.md5sum.length() != 0) {
			exe = queryExecutableByMd5(query.md5sum, response.manage);
		}
		else {
			exe = exeTable.querySingleExecutable(response.manage, query.name_exec, query.arch,
				query.name_compiler);
			if (exe == null) {
				throw new LSHException("Could not (uniquely) match executable");
			}
		}
		for (FunctionEntry entry : query.functionKeys) {
			FunctionDescription func =
				queryByNameAddress(response.manage, exe, entry.funcName, entry.address, true);
			if (func == null) {
				throw new LSHException("Could not find function: " + entry.funcName);
			}
			response.correspond.add(func);
		}

		TreeMap<RowKey, FunctionDescription> funcmap = new TreeMap<>();
		response.manage.generateFunctionIdMap(funcmap);
		for (FunctionDescription element : response.correspond) {
			fillinChildren(element, response.manage, funcmap);
		}
	}

	/**
	 * Entry point for the CreateDatabase command
	 * @param query the query to execute
	 * @throws LSHException if the configuration template cannot be loaded
	 * @throws SQLException if the {@link #generate(Configuration)} call fails
	 */
	private void fdbDatabaseCreate(CreateDatabase query) throws LSHException, SQLException {
		ResponseInfo response = query.inforesponse;
		Configuration config = FunctionDatabase.loadConfigurationTemplate(query.config_template);
		// Copy in any overriding fields in the query
		if (query.info.databasename != null) {
			config.info.databasename = query.info.databasename;
		}
		if (query.info.owner != null) {
			config.info.owner = query.info.owner;
		}
		if (query.info.description != null) {
			config.info.description = query.info.description;
		}
		if (!query.info.trackcallgraph) {
			config.info.trackcallgraph = query.info.trackcallgraph;
		}
		if (query.info.functionTags != null) {
			checkStrings(query.info.functionTags, "function tags",
				FunctionTagBSimFilterType.MAX_TAG_COUNT);
			config.info.functionTags = query.info.functionTags;
		}
		if (query.info.execats != null) {
			checkStrings(query.info.execats, "categories", -1);
			config.info.execats = query.info.execats;
		}
		generate(config);
		response.info = config.info;
	}

	private static void checkStrings(List<String> list, String type, int limit)
			throws LSHException {
		if (limit > 0 && list.size() > limit) {
			throw new LSHException("Too many " + type + " specified (limit=" +
				FunctionTagBSimFilterType.MAX_TAG_COUNT + "): " + list.size());
		}
		Set<String> names = new HashSet<>();
		for (String name : list) {
			if (!CategoryRecord.enforceTypeCharacters(name)) {
				throw new LSHException("Bad characters in one or more proposed " + type);
			}
			if (!names.add(name)) {
				throw new LSHException("Duplicate " + type + " entry specified: " + name);
			}
		}
	}

	/**
	 * Entry point for the InstallCategoryRequest command
	 * @param query the query to execute
	 * @throws LSHException if the category is invalid or already exists
	 * @throws SQLException if there is an error issuing the query
	 */
	private void fdbInstallCategory(InstallCategoryRequest query)
			throws LSHException, SQLException {
		ResponseInfo response = query.installresponse;
		if (!CategoryRecord.enforceTypeCharacters(query.type_name)) {
			throw new LSHException("Bad characters in proposed category type");
		}
		if (query.isdatecolumn) {
			info.dateColumnName = query.type_name;
			keyValueTable.insert("datecolumn", info.dateColumnName);
			response.info = info;
			return;
		}
		// Check for existing category
		if (info.execats != null) {
			for (String cat : info.execats) {
				if (cat.equals(query.type_name)) {
					throw new LSHException("Executable category already exists");
				}
			}
		}
		if (info.execats == null) {
			info.execats = new ArrayList<>();
		}
		info.execats.add(query.type_name);
		keyValueTable.writeExecutableCategories(info);
		response.info = info;
	}

	/**
	 * Returns a list of all function tags in the database.
	 * 
	 * @return list of function tags
	 */
	public List<String> getFunctionTags() {
		return info.functionTags;
	}

	/**
	 * Entry point for the InstallTagRequest command
	 * @param query the install query to execute
	 * @throws LSHException if the function tag already exists or is not valid
	 * @throws SQLException if there is an error issuing the query
	 */
	private void fdbInstallTag(InstallTagRequest query) throws LSHException, SQLException {
		ResponseInfo response = query.installresponse;
		if (!CategoryRecord.enforceTypeCharacters(query.tag_name)) {
			throw new LSHException("Bad characters in proposed function tag");
		}
		// Check for existing tag
		if (info.functionTags != null) {
			if (info.functionTags.contains(query.tag_name)) {
				throw new LSHException("Function tag already exists");
			}
		}
		if (info.functionTags == null) {
			info.functionTags = new ArrayList<>();
		}
		// There are only 32-bits of space in the function record reserved for storing the presence of tags
		if (info.functionTags.size() >= FunctionTagBSimFilterType.MAX_TAG_COUNT) {
			throw new LSHException(
				"Cannot allocate new function tag: " + query.tag_name + " - Column space is full");
		}
		info.functionTags.add(query.tag_name);
		keyValueTable.writeFunctionTags(info);
		response.info = info;
	}

	/**
	 * Entry point for the InstallMetadataRequest command
	 * @param query the query to execute
	 * @throws SQLException if basic info can't be written to the table
	 */
	private void fdbInstallMetadata(InstallMetadataRequest query) throws SQLException {
		ResponseInfo response = query.installresponse;
		if (query.dbname != null) {
			info.databasename = query.dbname;
		}
		if (query.owner != null) {
			info.owner = query.owner;
		}
		if (query.description != null) {
			info.description = query.description;
		}
		if (query.dbname != null || query.owner != null || query.description != null) {
			keyValueTable.writeBasicInfo(info);
		}
		response.info = info;
	}

	/**
	 * Entry point for the QueryDelete command
	 * @param query the query to execute
	 * @throws SQLException if there is an error issuing the query
	 * @throws LSHException if there is an error issuing the query
	 */
	private void fdbDelete(QueryDelete query) throws SQLException, LSHException {
		ResponseDelete response = query.respdelete;
		for (ExeSpecifier spec : query.exelist) {
			DescriptionManager manage = new DescriptionManager();
			ExecutableRecord erec = null;
			boolean commit = false;
			beginTransaction(true);
			try {
				if (spec.exemd5 != null && spec.exemd5.length() != 0) {
					ExecutableRow row = exeTable.queryMd5ExeMatch(spec.exemd5);
					if (row != null) {
						erec = exeTable.makeExecutableRecord(manage, row);
					}
				}
				else {
					erec = exeTable.querySingleExecutable(manage, spec.exename, spec.arch,
						spec.execompname);
				}
				if (erec == null) {
					response.missedlist.add(spec);
					continue;
				}
				ResponseDelete.DeleteResult delrec = new ResponseDelete.DeleteResult();
				delrec.md5 = erec.getMd5();
				delrec.name = erec.getNameExec();
				List<FunctionDescription> funclist = new ArrayList<>();
				queryAllFunc(funclist, erec, manage, 0);
				Set<IdHistogram> table = IdHistogram.buildVectorIdHistogram(funclist.iterator());
				deleteVectors(table.iterator());
				delrec.funccount = deleteExecutable(erec, funclist, (info.execats != null));
				response.reslist.add(delrec);
				commit = true;
			}
			finally {
				endTransaction(commit);
			}
		}
	}

	/**
	 * Entry point for the QueryUpdate command
	 * @param query the query to execute
	 * @throws LSHException if there is an error issuing the query
	 * @throws SQLException if there is an error issuing the query
	 */
	private void fdbUpdate(QueryUpdate query) throws LSHException, SQLException {
		ResponseUpdate response = query.updateresponse;
		for (ExecutableRecord erec : query.manage.getExecutableRecordSet()) {
			int res = updateExecutable(query.manage, erec, response.badfunc, info.execats != null);
			if (res < 0) {
				response.badexe.add(erec);
			}
			else {
				if ((res & 1) != 0) {
					response.exeupdate += 1;
				}
				response.funcupdate += res >> 1;
			}
		}
	}

	/**
	 * Entry point for QueryOptionalExist command
	 * @param query is the parameters for the query
	 * @throws SQLException for problems with the connection
	 */
	private void fdbOptionalExist(QueryOptionalExist query) throws SQLException {
		ResponseOptionalExist response = query.optionalresponse;
		OptionalTable table =
			getOptionalTable(query.tableName, query.keyType, query.valueType, true);
		response.tableExists = (table != null);
		response.wasCreated = false;
		if (table == null && query.attemptCreation) {
			table = getOptionalTable(query.tableName, query.keyType, query.valueType, false);
			table.createTable();
			response.wasCreated = true;
		}
		else if (table != null && query.clearTable) {
			table.clearTable();
		}
	}

	/**
	 * Entry point for the QueryOptionalValues command
	 * @param query is the parameters for the query
	 * @throws SQLException for problems with the connection
	 */
	private void fdbQueryOptionalValues(QueryOptionalValues query) throws SQLException {
		ResponseOptionalValues response = query.optionalresponse;
		OptionalTable table =
			getOptionalTable(query.tableName, query.keyType, query.valueType, true);
		if (table == null) {
			response.resultArray = null;
			response.tableExists = false;
			return;
		}
		response.tableExists = true;
		response.resultArray = new Object[query.keys.length];
		for (int i = 0; i < response.resultArray.length; ++i) {
			response.resultArray[i] = table.readValue(query.keys[i]);
		}
	}

	/**
	 * Entry point for the InsertOptionalValues command
	 * @param query is the parameters for the command
	 * @throws SQLException for problems with the connection
	 */
	private void fdbInsertOptionalValues(InsertOptionalValues query) throws SQLException {
		ResponseOptionalExist response = query.optionalresponse;
		OptionalTable table =
			getOptionalTable(query.tableName, query.keyType, query.valueType, true);
		response.wasCreated = false;
		if (table == null) {
			response.tableExists = false;
			return;
		}
		response.tableExists = true;
		beginTransaction(false);
		boolean commit = false;
		try {
			table.lockForWrite();
			for (int i = 0; i < query.keys.length; ++i) {
				table.writeValue(query.keys[i], query.values[i]);
			}
			commit = true;
		}
		finally {
			endTransaction(commit);
		}
	}
}
