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
package ghidra.features.bsim.query.facade;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Set;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.app.decompiler.DecompileException;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.FunctionDatabase.ConnectionType;
import ghidra.features.bsim.query.FunctionDatabase.Status;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.protocol.*;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A simple class that allows the user to query a server for functions that match a given 
 * set of functions.
 */
public class SimilarFunctionQueryService implements AutoCloseable {

	private FunctionDatabase database = null;

	private Program program; // program associated with signature generator
	private GenSignatures signatureGenerator; // Cache of signature information collected so far
	private int numStages; // Number of stages to place query with,   0 means get from query

	public SimilarFunctionQueryService(Program program) {
		this.program = program;
		numStages = 0;
	}

	// for testing--dependency injection
	SimilarFunctionQueryService(Program program, FunctionDatabase database) {
		this.program = program;
		this.database = database;
		numStages = 0;
	}

	/**
	 * Given a list of functions to query, prepare the final QueryNearest object which will be marshalled to the
	 * server.  This involves generating the signatures for each of the function and accumulating their
	 * FunctionDescriptions
	 * @param queryInfo   is the high-level form of query, with the list of FunctionSymbols and other parameters
	 * @param monitor the task monitor
	 * @return the QueryNearest object ready for the queryStaged method
	 * @throws QueryDatabaseException if transferring functions fails
	 */
	public QueryNearest generateQueryNearest(SFQueryInfo queryInfo, TaskMonitor monitor)
			throws QueryDatabaseException {
		QueryNearest result = queryInfo.buildQueryNearest();
		doSignatureGeneration(queryInfo.getFunctions(), monitor);
		FunctionSymbolIterator iter =
			new FunctionSymbolIterator(queryInfo.getFunctions().iterator());
		try {
			signatureGenerator.transferCachedFunctions(result.manage, iter,
				queryInfo.getPreFilter());
		}
		catch (LSHException e) {
			throw new QueryDatabaseException(e.getMessage());
		}
		return result;
	}

	public QueryNearestVector generateQueryNearestVector(SFOverviewInfo overviewInfo,
			TaskMonitor monitor) throws QueryDatabaseException {
		QueryNearestVector result = overviewInfo.buildQueryNearestVector();
		doSignatureGeneration(overviewInfo.getFunctions(), monitor);
		FunctionSymbolIterator iter =
			new FunctionSymbolIterator(overviewInfo.getFunctions().iterator());
		try {
			signatureGenerator.transferCachedFunctions(result.manage, iter,
				overviewInfo.getPreFilter());
		}
		catch (LSHException e) {
			throw new QueryDatabaseException(e.getMessage());
		}
		return result;
	}

	/**
	 * Issue password change request to the server
	 * @param username to change
	 * @param newPassword is password data
	 * @return null if change was successful, or the error message
	 */
	@Deprecated
	public String changePassword(String username, char[] newPassword) {
		if (database == null || database.getStatus() != Status.Ready) {
			return "Connection not established";
		}
		PasswordChange passwordChange = new PasswordChange();
		passwordChange.username = username;
		passwordChange.newPassword = newPassword;
		ResponsePassword response = passwordChange.execute(database);
		if (!response.changeSuccessful) {
			return response.errorMessage;
		}
		return null;
	}

	/**
	 * Query the given server with the parameters provider by <tt>queryInfo</tt>.
	 * 
	 * @param queryInfo a query info object containing the settings for the query
	 * @param listener is the listener to be informed of the query status and incremental results 
	 * 		coming back, may be null
	 * @param monitor the task monitor to use; can be null
	 * @return the result object containing the retrieved similar functions; null if the query
	 *         was cancelled
	 * @throws QueryDatabaseException if the query execution fails
	 * @throws CancelledException if the query is cancelled by the user
	 */
	public SFQueryResult querySimilarFunctions(SFQueryInfo queryInfo,
			SFResultsUpdateListener<SFQueryResult> listener, TaskMonitor monitor)
			throws QueryDatabaseException, CancelledException {
		SFQueryResult result = null;
		try {
			if (database == null || database.getStatus() != Status.Ready) {
				throw new QueryDatabaseException("Connection with database not established");
			}
			if (monitor == null) {
				monitor = TaskMonitor.DUMMY;
			}
			if (listener == null) {
				listener = new NullListener<>();
			}

			//
			// Perform the required initialization:
			// -Initialize signature generator
			// -Hash the functions
			// -Create the query
			// -Create the staging
			//

			QueryNearest query = generateQueryNearest(queryInfo, monitor);
			int localNumStages = numStages;
			if (localNumStages == 0) {
				int funcsPerStage = database.getQueriedFunctionsPerStage();
				localNumStages = queryInfo.getNumberOfStages(funcsPerStage);
			}
			StagingManager stagingManager =
				createStagingManager(queryInfo.getFunctions().size(), localNumStages);

			//
			// Perform the query
			//
			ResponseNearest response =
				(ResponseNearest) doQuery(query, stagingManager, listener, monitor);

			//
			// Create the results for our facade interface
			//
			result =
				new SFQueryResult(queryInfo, database.getURLString(), database.getInfo(), response);
		}
		catch (LSHException e) {
			throw new QueryDatabaseException(e.getMessage());
		}
		finally {
			listener.setFinalResult(result);
		}
		return result;
	}

	/**
	 * Query the given server for similar function overview information
	 * @param overviewInfo is details of the overview query
	 * @param listener is the listener to be informed of the query status and incremental results 
	 * 		coming back, may be null
	 * @param monitor the task monitor
	 * @return the ResponseNearestVector
	 * @throws QueryDatabaseException if the database connection cannot be established
	 * @throws CancelledException if the query is cancelled by the user
	 */
	public ResponseNearestVector overviewSimilarFunctions(SFOverviewInfo overviewInfo,
			SFResultsUpdateListener<ResponseNearestVector> listener, TaskMonitor monitor)
			throws QueryDatabaseException, CancelledException {
		ResponseNearestVector response = null;
		try {
			if (database == null || database.getStatus() != Status.Ready) {
				throw new QueryDatabaseException("Connection to database not established");
			}
			if (monitor == null) {
				monitor = TaskMonitor.DUMMY;
			}
			if (listener == null) {
				listener = new NullListener<>();
			}

			QueryNearestVector query = generateQueryNearestVector(overviewInfo, monitor);
			int localNumStages = numStages;
			if (localNumStages == 0) {
				int funcsPerStage = database.getOverviewFunctionsPerStage();
				localNumStages = overviewInfo.getNumberOfStages(funcsPerStage);
			}
			StagingManager stagingManager =
				createStagingManager(overviewInfo.getFunctions().size(), localNumStages);

			try {
				response =
					(ResponseNearestVector) doQuery(query, stagingManager, listener, monitor);
			}
			catch (LSHException e) {
				throw new QueryDatabaseException(e.getMessage());
			}
		}
		finally {
			listener.setFinalResult(response);
		}
		return response;
	}

	/**
	 * A lower-level (more flexible) query of the database.  The query is not staged.
	 * @param query is the raw query information
	 * @param stagingManager is how to split up the query, can be null
	 * @param listener is the listener to be informed of the query status and incremental results 
	 * 		coming back, may be null
	 * @param monitor the task monitor
	 * @return the raw response record from the database
	 * @throws QueryDatabaseException if the database connection cannot be established
	 * @throws CancelledException if the query is cancelled by the user
	 */
	public QueryResponseRecord queryRaw(BSimQuery<?> query, StagingManager stagingManager,
			SFResultsUpdateListener<QueryResponseRecord> listener, TaskMonitor monitor)
			throws QueryDatabaseException, CancelledException {
		QueryResponseRecord response = null;
		try {
			if (database == null || database.getStatus() != Status.Ready) {
				throw new QueryDatabaseException("Connection to database not established");
			}
			if (monitor == null) {
				monitor = TaskMonitor.DUMMY;
			}
			if (listener == null) {
				listener = new NullListener<>();
			}
			if (stagingManager == null) {
				stagingManager = new NullStaging();
			}
			response = doQuery(query, stagingManager, listener, monitor);
		}
		catch (LSHException e) {
			throw new QueryDatabaseException(e.getMessage());
		}
		finally {
			listener.setFinalResult(response);
		}
		return response;
	}

	public void dispose() {
		close();
	}

	@Override
	public void close() {
		if (database != null) {
			database.close();
			database = null;
		}
		if (signatureGenerator != null) {
			signatureGenerator.dispose();
			signatureGenerator = null;
		}
	}

	public void setNumberOfStages(int val) {
		numStages = val;
	}

	public void updateProgram(Program newProgram) {
		if (this.program != newProgram) {
			this.program = newProgram;
			this.signatureGenerator = null;
		}
	}

	private QueryResponseRecord doQuery(BSimQuery<?> query, StagingManager stagingManager,
			SFResultsUpdateListener<?> listener, TaskMonitor monitor)
			throws LSHException, CancelledException {

		boolean haveMore = stagingManager.initialize(query);
		query.buildResponseTemplate();

		QueryResponseRecord globalResponse = query.getResponse();

		monitor.setMessage("Querying database");
		monitor.initialize(stagingManager.getTotalSize());

		while (haveMore) {
			monitor.checkCancelled();

			// Get the current staged form of the query
			BSimQuery<?> stagedQuery = stagingManager.getQuery();

			QueryResponseRecord response = stagedQuery.execute(database);
			if (response != null) {

				if (globalResponse != response) {
					globalResponse.mergeResults(response); // Merge the staged response with the global response
				}

				listener.resultAdded(response);

				haveMore = stagingManager.nextStage();
				if (haveMore) {
					stagedQuery.clearResponse(); // Make space for next stage
				}
				monitor.setProgress(stagingManager.getQueriesMade());
			}
			else {
				throw new LSHException(database.getLastError().message);
			}
		}

		return globalResponse;
	}

	/**
	 * Return the {@link BSimServerInfo server info object} for this database
	 * @return the server info object or null if not currently associated with 
	 * a {@link FunctionDatabase}.
	 */
	public BSimServerInfo getServerInfo() {
		if (database == null) {
			return null;
		}
		return database.getServerInfo();
	}

	public Status getDatabaseStatus() {
		if (database == null) {
			return Status.Unconnected;
		}
		return database.getStatus();
	}

	public ConnectionType getDatabaseConnectionType() {
		if (database == null) {
			return ConnectionType.Unencrypted_No_Authentication;
		}
		return database.getConnectionType();
	}

	public DatabaseInformation getDatabaseInformation() {
		if (database == null) {
			return null;
		}
		return database.getInfo();
	}

	public String getUserName() {
		if (database == null) {
			return null;
		}
		return database.getUserName();
	}

	public LSHVectorFactory getLSHVectorFactory() {
		if (database == null) {
			return null;
		}
		return database.getLSHVectorFactory();
	}

	public FunctionDatabase.Error getLastError() {
		if (database == null) {
			return null;
		}
		return database.getLastError();
	}

	/**
	 * Returns a string explaining the database compatibility between this client and the server.
	 * 
	 * @return a string explaining the compatibility, or null if it could not be determined
	 */
	public String getDatabaseCompatibility() {
		if (database == null) {
			return null;
		}
		DatabaseInformation info = database.getInfo();
		if (info == null) {
			return null;
		}
		int compare = database.compareLayout();
		if (compare < 0) {
			return "This client is incompatible with the earlier database format on the server";
		}
		else if (compare > 0) {
			return "The server is using a later database format than is supported by this client";
		}
		return null;
	}

	// NOTE: Method overriden for testing
	protected FunctionDatabase createDatabase(String urlString) throws MalformedURLException {
		URL url = BSimClientFactory.deriveBSimURL(urlString);
		return BSimClientFactory.buildClient(url, false);
	}

	public void initializeDatabase(String serverURLString) throws QueryDatabaseException {
		if (isSameDatabase(serverURLString)) {
			if (database.getStatus() == Status.Ready) {
				return; // Trying to connect with server which is still ready
			}
		}

		if (database != null) {
			database.close(); // Shutdown old connection (or erroneous connection)
			database = null;
		}

		try {
			database = createDatabase(serverURLString);
		}
		catch (MalformedURLException e) {
			throw new QueryDatabaseException("Bad database URL: " + e.getMessage());
		}
		boolean success = database.initialize();
		if (!success) {
			String errorMsg = "";
			if (database.getLastError() != null) {
				errorMsg = database.getLastError().message;
			}

			throw new QueryDatabaseException(errorMsg);
		}
	}

	private boolean isSameDatabase(String serverURLString) {
		if (database == null) {
			return false;
		}
		return database.getURLString().equals(serverURLString);
	}

	private void doSignatureGeneration(Set<FunctionSymbol> functions, TaskMonitor monitor)
			throws QueryDatabaseException {
		if (functions.isEmpty()) {
			return;
		}

		if (signatureGenerator == null) {
			signatureGenerator = createSignatureGenerator();
		}
		try {
			signatureGenerator.setVectorFactory(database.getLSHVectorFactory());
		}
		catch (LSHException e1) {
			throw new QueryDatabaseException(e1);
		}

		monitor.setMessage("Hashing function signatures...");
		FunctionSymbolIterator iter = new FunctionSymbolIterator(functions.iterator());
		int count = functions.size();
		try {
// TODO: do this work in a loop so that one failure doesn't stop the entire process...the 
//		 downside is losing parallelization
			signatureGenerator.scanFunctions(iter, count, monitor);
		}
		catch (DecompileException e) {
			throw new QueryDatabaseException(e);
		}
	}

	private GenSignatures createSignatureGenerator() throws QueryDatabaseException {
		try {
			GenSignatures newSignatureGenerator = new GenSignatures(false);
			newSignatureGenerator.openProgram(program, null, null, null, null, null);
			return newSignatureGenerator;
		}
		catch (LSHException e) {
			throw new QueryDatabaseException("Unable to signature functions", e);
		}
	}

	private StagingManager createStagingManager(int numqueries, int stages) {
		if (stages == 1) {
			return new NullStaging();
		}

		int numberOfFunctionsPerQuery;
		if (stages > numqueries) {
			// when the number of stages is greater than the number of functions, lower the stage
			// count to execute one function at a time (stages becomes numqueries)
			numberOfFunctionsPerQuery = 1;
		}
		else {
			numberOfFunctionsPerQuery = (int) Math.ceil(numqueries / stages);
		}

		return new FunctionStaging(numberOfFunctionsPerQuery);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * A dumby listener that will be called as incremental results arrive from database queries.  
	 * No action is tacken for all results
	 * @param <R> the final result implementation class.
	 */
	private class NullListener<R> implements SFResultsUpdateListener<R> {

		@Override
		public void resultAdded(QueryResponseRecord response) {
			// no-op
		}

//		@Override
//		public void updateStatus(String message, MessageType type) {
//			// no-op
//		}

		@Override
		public void setFinalResult(R result) {
			// TODO Auto-generated method stub
		}
	}
}
