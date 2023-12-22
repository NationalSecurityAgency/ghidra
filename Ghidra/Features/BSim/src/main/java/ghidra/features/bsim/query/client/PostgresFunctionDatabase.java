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

import java.io.IOException;
import java.net.URL;
import java.sql.*;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import generic.lsh.vector.LSHVector;
import generic.lsh.vector.WeightedLSHCosineVectorFactory;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.BSimPostgresDBConnectionManager.BSimPostgresDataSource;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.features.bsim.query.client.tables.CachedStatement;
import ghidra.features.bsim.query.client.tables.SQLStringTable;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.protocol.*;

/**
 * Defines the BSim {@link FunctionDatabase} backed by a PostgreSQL database.
 * 
 * Simple, one-column tables that only contain string data use the
 * {@link SQLStringTable} class and are defined in this class. More complex
 * tables are defined in their own classes in the
 * {@link ghidra.features.bsim.query.client.tables} package.
 * 
 */
public final class PostgresFunctionDatabase
	extends AbstractSQLFunctionDatabase<WeightedLSHCosineVectorFactory> {

	// NOTE: Previously named ColumnDatabase

	static {
		// FIXME: Decide how and where logging should be established
		// FIXME: Logging should be disabled by default
		Logger postgresLogger = Logger.getLogger("org.postgresql.Driver");
		postgresLogger.setLevel(Level.FINEST);
	}

	// Indicates the version of the db table configuration.  This needs to be updated
	// whenever changes are made to the table structure.
	public static final int LAYOUT_VERSION = 6;

	private static final String DEFAULT_DATABASE_NAME = "postgres";

	private BSimPostgresDataSource postgresDs;
	private boolean asynchronous; // Should database commits be asynchronous

	// Persist SQL statements as class members so we don't have to recreate them every
	// time they're needed.
	private final CachedStatement<Statement> reusableStatement = new CachedStatement<>();
	private final CachedStatement<PreparedStatement> selectVectorByRowIdStatement =
		new CachedStatement<>();
	private final CachedStatement<PreparedStatement> selectNearestVectorStatement =
		new CachedStatement<>();

	public PostgresFunctionDatabase(URL postgresUrl, boolean async) {
		super(BSimPostgresDBConnectionManager.getDataSource(postgresUrl),
			FunctionDatabase.generateLSHVectorFactory(), LAYOUT_VERSION);
		postgresDs = (BSimPostgresDataSource) ds;
		asynchronous = async;
	}

	@Override
	public void close() {
		reusableStatement.close();
		selectVectorByRowIdStatement.close();
		selectNearestVectorStatement.close();
		super.close();
	}

	private Statement getReusableStatement() throws SQLException {
		return reusableStatement.prepareIfNeeded(() -> initConnection().createStatement());
	}

	/**
	 * Obtain an exclusive lock on the main tables. To be used when INSERTING, DELETING, or UPDATING
	 * to prevent concurrent changes to the tables.
	 * @throws SQLException if the server reports an error
	 */
	@Override
	protected void lockTablesForWrite() throws SQLException {
		String stmtstring = "LOCK TABLE exetable, desctable, vectable IN SHARE ROW EXCLUSIVE MODE";
		getReusableStatement().execute(stmtstring);
	}

	private void changePassword(Connection c, String username, char[] newPassword)
		throws SQLException {
		StringBuilder buffer = new StringBuilder();
		buffer.append("ALTER ROLE \"");
		buffer.append(username);
		buffer.append("\" WITH PASSWORD '");
		for (char ch : newPassword) {
			if (ch == '\'') {
				buffer.append(ch);		// Escape single quote by appending it twice
			}
			buffer.append(ch);
		}
		buffer.append('\'');
		// Don't think jdbc does anything to this statement to encrypt password before sending it.
		// The connection with the server SHOULD be under SSL at this point
		try (Statement st = c.createStatement()) {

			st.executeUpdate(buffer.toString());

			// update password to be used for new connections
			postgresDs.setPassword(username, newPassword);
		}
	}

	/**
	 * 
	 * @param st the database query statement
	 * @throws SQLException if there is a problem creating the query statement
	 */
	private void createVectorFunctions(Statement st) throws SQLException {
		st.executeUpdate("CREATE FUNCTION insert_vec(newvec lshvector,OUT ourhash BIGINT) AS $$" +
			" DECLARE" +
			"  curs1 CURSOR (key BIGINT) FOR SELECT count FROM vectable WHERE id = key FOR UPDATE;" +
			"  ourcount INTEGER;" + " BEGIN" + "  ourhash := lshvector_hash(newvec);" +
			"  OPEN curs1( ourhash );" + "  FETCH curs1 INTO ourcount;" + "  IF FOUND THEN" +
			"    UPDATE vectable SET count = ourcount + 1 WHERE CURRENT OF curs1;" + "  ELSE" +
			"    INSERT INTO vectable (id,count,vec) VALUES(ourhash,1,newvec);" + "  END IF;" +
			"  CLOSE curs1;" + " END;" + " $$ LANGUAGE plpgsql;");
		st.executeUpdate(
			"CREATE FUNCTION remove_vec(vecid BIGINT,countdiff INTEGER) RETURNS INTEGER AS $$" +
				"DECLARE" +
				"  curs1 CURSOR (key BIGINT) FOR SELECT count FROM vectable WHERE id = key FOR UPDATE;" +
				"  ourcount INTEGER;" + "  rescode INTEGER;" + "BEGIN" + "  rescode = -1;" +
				"  OPEN curs1( vecid );" + "  FETCH curs1 INTO ourcount;" +
				"  IF FOUND AND ourcount > countdiff THEN" +
				"    UPDATE vectable SET count = ourcount - countdiff WHERE CURRENT OF curs1;" +
				"    rescode = 0;" + "  ELSIF FOUND THEN" +
				"    DELETE FROM vectable WHERE CURRENT OF curs1;" + "    rescode = 1;" +
				"  END IF;" + "  CLOSE curs1;" + "  RETURN rescode;" + "END;" +
				"$$ LANGUAGE plpgsql;");
	}

	/**
	 * 
	 * @throws SQLException if there is an error creating/executing the query
	 */
	private void serverLoadWeights(Connection db) throws SQLException {
		try (Statement st = db.createStatement();
			ResultSet rs = st.executeQuery("SELECT lsh_load()")) {
			while (rs.next()) {
				// int val = rs.getInt(1);
			}
		}
	}

	@Override
	protected void initializeDatabase(Configuration config) throws SQLException {

		Connection db = initConnection();
		serverLoadWeights(db);

		if (asynchronous) {
			try (Statement st = db.createStatement()) {
				// Tell server to do asynchronous commits. This speeds up large
				// ingests with a (slight) danger of
				// losing the most recent commits if the server crashes (NOTE:
				// database integrity should still be recoverable)
				st.executeUpdate("SET LOCAL synchronous_commit TO OFF");
			}
		}

		super.initializeDatabase(config);
	}

	@Override
	protected void generateRawDatabase() throws SQLException {
		BSimServerInfo serverInfo = postgresDs.getServerInfo();
		BSimServerInfo defaultServerInfo = new BSimServerInfo(DBType.postgres,
			serverInfo.getServerName(), serverInfo.getPort(), DEFAULT_DATABASE_NAME);
		String createdbstring = "CREATE DATABASE \"" + serverInfo.getDBName() + '"';
		BSimPostgresDataSource defaultDs =
			BSimPostgresDBConnectionManager.getDataSource(defaultServerInfo);
		try (Connection db = defaultDs.getConnection(); Statement st = db.createStatement()) {
			st.executeUpdate(createdbstring);
			postgresDs.initializeFrom(defaultDs);
		}
		finally {
			defaultDs.dispose();
		}
	}

	@Override
	protected void createDatabase(Configuration config) throws SQLException {
		try {
			super.createDatabase(config);

			Connection db = super.initConnection();
			try (Statement st = db.createStatement()) {

				st.executeUpdate("CREATE EXTENSION IF NOT EXISTS lshvector");
				st.executeUpdate(
					"CREATE TABLE vectable(id BIGINT UNIQUE,count INTEGER,vec lshvector)");
				st.executeUpdate(
					"CREATE INDEX vectable_vec_idx ON vectable USING gin (vec gin_lshvector_ops)");
				createVectorFunctions(st);

				st.executeUpdate("REVOKE ALL ON SCHEMA PUBLIC FROM PUBLIC");
				st.executeUpdate("GRANT USAGE ON SCHEMA PUBLIC TO PUBLIC");
				st.executeUpdate("GRANT SELECT ON ALL TABLES IN SCHEMA PUBLIC TO PUBLIC");
				st.executeUpdate("GRANT USAGE ON ALL SEQUENCES IN SCHEMA PUBLIC TO PUBLIC");

				serverLoadWeights(db);

				if (asynchronous) {
					// Tell server to do asynchronous commits. This speeds up large
					// ingests with a (slight) danger of
					// losing the most recent commits if the server crashes (NOTE:
					// database integrity should still be recoverable)
					st.executeUpdate("SET LOCAL synchronous_commit TO OFF");
				}
			}
		}
		catch (final SQLException err) {
			throw new SQLException("Could not create database: " + err.getMessage());
		}
	}

	/**
	 * 
	 * @throws SQLException if there is a problem creating or executing the query
	 */
	private void dropIndex(Connection c) throws SQLException {
		try (Statement st = c.createStatement()) {
			st.execute("DROP INDEX vectable_vec_idx");
		}
	}

	/**
	 * 
	 * @throws SQLException if there is a problem creating or executing the query
	 */
	private void rebuildIndex(Connection c) throws SQLException {
		try (Statement st = c.createStatement();
			ResultSet rs = st.executeQuery("SELECT lsh_reload()")) {
			st.execute("SET maintenance_work_mem TO '2GB'");
			st.execute(
				"CREATE INDEX vectable_vec_idx ON vectable USING gin (vec gin_lshvector_ops)");
		}
	}

	/**
	 * Attempt to preload some of the main tables and indices into cache or RAM
	 * 
	 * @param mainIndex
	 *            For the main index -- 0=don't load 1=load into RAM 2=load into
	 *            cache
	 * @param secondaryIndex
	 *            For the secondary index -- 0=don't load 1=load into RAM 2=load
	 *            into cache
	 * @param vectors
	 *            For vectors -- 0=don't load 1=load into RAM 2=load into cache
	 * @return the number of blocks loaded for the main index
	 * @throws SQLException if there is a problem creating or executing the query
	 */
	private int preWarm(Connection c, int mainIndex, int secondaryIndex, int vectors)
		throws SQLException {
		try (Statement st = c.createStatement()) {
			// Try to load the entire main index into the PostgreSQL cache
			int res = -1;
			String queryString;
			st.execute("CREATE EXTENSION IF NOT EXISTS pg_prewarm");
			if (mainIndex != 0) {
				if (mainIndex == 1) {
					queryString = "SELECT pg_prewarm('vectable_vec_idx','read')";
				}
				else {
					queryString = "SELECT pg_prewarm('vectable_vec_idx')";
				}
				try (ResultSet rs = st.executeQuery(queryString)) {
					if (rs.next()) {
						res = rs.getInt(1); // Number of blocks that were successfully prewarmed
						while (rs.next()) { // Shouldn't be any more rows
							// TODO: Should be no need to exhaust results
						}
					}
				}
			}
			if (secondaryIndex != 0) {
				// Try to convince the OS to load the secondary vector table index
				// into RAM
				if (secondaryIndex == 1) {
					queryString = "SELECT pg_prewarm('vectable_id_key','read')";
				}
				else {
					queryString = "SELECT pg_prewarm('vectable_id_key')";
				}
				try (ResultSet rs = st.executeQuery(queryString)) {
					while (rs.next()) {
						// TODO: Should be no need to exhaust results
						// int val = rs.getInt(1);
					}
				}
			}
			if (vectors != 0) {
				// Try to convince the OS to load the vector table into RAM
				if (vectors == 1) {
					queryString = "SELECT pg_prewarm('vectable','read')";
				}
				else {
					queryString = "SELECT pg_prewarm('vectable')";
				}
				try (ResultSet rs = st.executeQuery(queryString)) {
					while (rs.next()) {
						// TODO: Should be no need to exhaust results
						// int val = rs.getInt(1);
					}
				}
			}
			st.execute("DROP EXTENSION pg_prewarm");

			return res;
		}
	}

	/**
	 * Make sure the vector corresponding to the SignatureRecord is inserted into the vectable
	 * @param sigrec is the SignatureRecord
	 * @return the computed id of the vector
	 * @throws SQLException if there is a problem creating or executing the query
	 */
	@Override
	protected long storeSignatureRecord(SignatureRecord sigrec) throws SQLException {
		String sql = "SELECT insert_vec( '" + sigrec.getLSHVector().saveSQL() + "')";
		try (ResultSet rs = getReusableStatement().executeQuery(sql)) {
			if (!rs.next()) {
				throw new SQLException("Did not get vector id after insertion");
			}
			return rs.getLong(1);
		}
	}

	/**
	 * Low level count decrement of a vector record from vectable, if count
	 * reaches zero, the record is deleted
	 * @param c database connection
	 * @param id vector row ID
	 * @param countdiff the amount to subtract from count
	 * @return 0 if decrement short of 0, return 1 if record was removed, return
	 *         -1 if there was a problem
	 * @throws SQLException if there is a problem creating or executing the query
	 */
	@Override
	protected int deleteVectors(long id, int countdiff) throws SQLException {
		int res = -100;
		String sql =
			"SELECT remove_vec( " + Long.toString(id) + ',' + Integer.toString(countdiff) + ")";
		try (ResultSet rs = getReusableStatement().executeQuery(sql)) {
			if (!rs.next()) {
				throw new SQLException("Did not get result code after deletion");
			}
			res = rs.getInt(1);
		}
		return res;
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
	@Override
	protected int queryNearestVector(List<VectorResult> resultset, LSHVector vec,
		double simthresh, double sigthresh, int max) throws SQLException {
		PreparedStatement s =
			selectNearestVectorStatement.prepareIfNeeded(() -> initConnection().prepareStatement(
				"WITH const(cvec) AS (VALUES( lshvector_in( CAST( ? AS cstring) ) ) )," +
					" comp AS (" +
					" SELECT id,count,cvec,vec,lshvector_compare(cvec,vec) AS cfunc FROM const,vectable" +
					"        WHERE cvec % vec)" +
					" SELECT id,count,(comp.cfunc).sim,(comp.cfunc).sig,vec FROM comp" +
					" WHERE (comp.cfunc).sim > ? AND (comp.cfunc).sig > ?" +
					" ORDER BY (comp.cfunc).sim DESC" + " LIMIT ?"));
		s.setString(1, vec.saveSQL());
		s.setDouble(2, simthresh);
		s.setDouble(3, sigthresh);
		s.setInt(4, max);

		int total = 0;
		try (ResultSet rs = s.executeQuery()) {
			while (rs.next()) {
				VectorResult curres = new VectorResult();
				resultset.add(curres);
				curres.vectorid = rs.getLong(1);
				curres.hitcount = rs.getInt(2);
				curres.sim = rs.getDouble(3);
				curres.signif = rs.getDouble(4);
				final String vecstring = rs.getString(5);
				try {
					curres.vec = vectorFactory.restoreVectorFromSql(vecstring);
				}
				catch (final IOException e) {
					throw new SQLException(e.getMessage());
				}
				total += curres.hitcount;
			}
			return total;
		}
	}

	@Override
	protected void queryNearestVector(QueryNearestVector query) throws SQLException {
		ResponseNearestVector response = query.nearresponse;
		response.totalvec = 0;
		response.totalmatch = 0;
		response.uniquematch = 0;

		int vectormax = query.vectormax;
		if (vectormax == 0) {
			vectormax = 2000000; // Really means a very big limit
		}

		Iterator<FunctionDescription> iter = query.manage.listAllFunctions();
		while (iter.hasNext()) {
			FunctionDescription frec = iter.next();
			SignatureRecord srec = frec.getSignatureRecord();
			if (srec == null) {
				continue;
			}
			LSHVector thevec = srec.getLSHVector();
			double len2 = vectorFactory.getSelfSignificance(thevec);
			if (len2 < query.signifthresh) {
				continue;
			}

			response.totalvec += 1;
			List<VectorResult> resultset = new ArrayList<>();

			queryNearestVector(resultset, thevec, query.thresh, query.signifthresh, vectormax);
			if (resultset.isEmpty()) {
				continue;
			}
			SimilarityVectorResult simres = new SimilarityVectorResult(frec);
			simres.addNotes(resultset);
			response.totalmatch += simres.getTotalCount();
			if (simres.getTotalCount() == 1) {
				response.uniquematch += 1;
			}
			response.result.add(simres);
		}
	}

	@Override
	protected VectorResult queryVectorId(long id) throws SQLException {
		PreparedStatement s = selectVectorByRowIdStatement.prepareIfNeeded(() -> initConnection()
			.prepareStatement("SELECT id,count,vec FROM vectable WHERE id = ?"));
		s.setLong(1, id);
		try (ResultSet rs = s.executeQuery()) {
			if (!rs.next()) {
				throw new SQLException("Bad vectable rowid");
			}
			VectorResult rowres;
			try {
				rowres = new VectorResult();
				rowres.vectorid = rs.getLong(1);
				rowres.hitcount = rs.getInt(2);
				rowres.vec = vectorFactory.restoreVectorFromSql(rs.getString(3));
			}
			catch (final IOException e) {
				throw new SQLException(e.getMessage());
			}

			return rowres;
		}

	}

	@Override
	public String getUserName() {
		return postgresDs.getUserName();
	}

	@Override
	public void setUserName(String userName) {
		if (postgresDs.getStatus() == Status.Ready) {
			throw new IllegalStateException("Connection has already been established");
		}
		postgresDs.setPreferredUserName(userName);
	}

	@Override
	public QueryResponseRecord doQuery(BSimQuery<?> query, Connection c)
		throws SQLException, LSHException, DatabaseNonFatalException {

		if (query instanceof PrewarmRequest q) {
			fdbPrewarm(q, c);
		}
		else if (query instanceof PasswordChange q) {
			fdbPasswordChange(q, c);
		}
		else if (query instanceof AdjustVectorIndex q) {
			fdbAdjustVectorIndex(q, c);
		}
		else {
			return super.doQuery(query, c);
		}
		return query.getResponse();
	}

	/**
	 * Entry point for the AdjustVectorIndex command
	 * @param query the query to execute
	 * @throws SQLException if there is a problem rebuilding or dropping the index
	 */
	private void fdbAdjustVectorIndex(AdjustVectorIndex query, Connection c) throws SQLException {
		ResponseAdjustIndex response = query.adjustresponse;
		response.success = false;
		if (query.doRebuild) {
			rebuildIndex(c);
		}
		else {
			dropIndex(c);
		}
		response.success = true;
	}

	/**
	 * Entry point for the PrewarmRequest command
	 * @param request the prewarm request
	 * @param c Postgres DB connection
	 * @throws SQLException if there is an error issuing the query
	 */
	private void fdbPrewarm(PrewarmRequest request, Connection c) throws SQLException {
		ResponsePrewarm response = request.prewarmresponse;
		response.blockCount = preWarm(c, request.mainIndexConfig, request.secondaryIndexConfig,
			request.vectorTableConfig);
	}

	private void fdbPasswordChange(PasswordChange query, Connection c) throws LSHException {
		ResponsePassword response = query.passwordResponse;
		if (query.username == null) {
			throw new LSHException("Missing username for password change");
		}
		if (query.newPassword == null || query.newPassword.length == 0) {
			throw new LSHException("No password provided");
		}
		response.changeSuccessful = true;		// Response parameters assuming success
		response.errorMessage = null;
		try {
			changePassword(c, query.username, query.newPassword);
		}
		catch (SQLException e) {
			response.changeSuccessful = false;
			response.errorMessage = e.getMessage();
		}
	}

	@Override
	public String formatBitAndSQL(String v1, String v2) {
		return "(" + v1 + " & " + v2 + ")";
	}

}
