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
package ghidra.features.bsim.query.file;

import java.net.URL;
import java.sql.*;
import java.util.*;

import generic.concurrent.*;
import generic.lsh.vector.LSHVector;
import generic.lsh.vector.VectorCompare;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.client.*;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.elastic.Base64VectorFactory;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager.BSimH2FileDataSource;
import ghidra.features.bsim.query.protocol.*;
import ghidra.util.task.TaskMonitor;

public class H2FileFunctionDatabase extends AbstractSQLFunctionDatabase<Base64VectorFactory> {

	public static final int OVERVIEW_FUNCS_PER_STAGE = 1024;
	public static final int QUERY_FUNCS_PER_STAGE = 256;
	private static final String H2_THREADPOOL_NAME = "H2_BSIM_THREADPOOL";

	// Indicates the version of the db table configuration.  This needs to be updated
	// whenever changes are made to the table structure.
	public static final int LAYOUT_VERSION = 1;

	private final BSimH2FileDataSource fileDs;

	private H2VectorTable vectorTable;
	private VectorStore vectorStore;

	/**
	 * Constructor used to connect to an existing H2 file database
	 * @param bsimURL local file URL for H2 database
	 */
	public H2FileFunctionDatabase(URL bsimURL) {
		this(BSimH2FileDBConnectionManager.getDataSource(bsimURL));
	}

	/**
	 * Constructor used to connect to an existing H2 file database
	 * @param serverInfo local file info for H2 database
	 */
	public H2FileFunctionDatabase(BSimServerInfo serverInfo) {
		this(BSimH2FileDBConnectionManager.getDataSource(serverInfo));
	}

	/**
	 * Constructor used to connect to an existing H2 file database
	 * @param ds local file H2 data source
	 */
	private H2FileFunctionDatabase(BSimH2FileDataSource ds) {
		super(ds, new Base64VectorFactory(), LAYOUT_VERSION);
		fileDs = ds;
		vectorStore = BSimVectorStoreManager.getVectorStore(getServerInfo());
		vectorTable = new H2VectorTable(vectorFactory, vectorStore);
	}

	@Override
	public void close() {
		vectorTable.close();
		super.close();
	}

	@Override
	protected void setConnectionOnTables(Connection db) {
		vectorTable.setConnection(db);
		super.setConnectionOnTables(db);
	}

	@Override
	protected Connection initConnection() throws SQLException {
		if (getStatus() != Status.Ready && !fileDs.exists()) {
			throw new SQLException(
				"Database does not exist: " + fileDs.getServerInfo().getDBName());
		}
		return super.initConnection();
	}

	@Override
	protected void generateRawDatabase() throws SQLException {
		BSimServerInfo serverInfo = fileDs.getServerInfo();
		if (fileDs.exists()) {
			throw new SQLException("Database already exists: " + serverInfo.getDBName());
		}
		try (Connection c = fileDs.getConnection()) {
			// do nothing - should throw exception on error
		}
	}

	@Override
	protected void createDatabase(Configuration config) throws SQLException {
		try {
			super.createDatabase(config);

			Connection db = initConnection();
			try (Statement st = db.createStatement()) {
				vectorTable.create(st);
			}
		}
		catch (final SQLException err) {
			throw new SQLException("Could not create database: " + err.getMessage());
		}
	}

	/**
	 * Create vector map which maps vector ID to {@link VectorStoreEntry}
	 * @return vector map
	 * @throws SQLException if error occurs while reading map data
	 */
	public Map<Long, VectorStoreEntry> readVectorMap() throws SQLException {
		return vectorTable.readVectors();
	}

	@Override
	protected int deleteVectors(long id, int countdiff) throws SQLException {
		return vectorTable.deleteVector(id, countdiff);
	}

	@Override
	public QueryResponseRecord doQuery(BSimQuery<?> query, Connection c)
		throws SQLException, LSHException, DatabaseNonFatalException {

		if (query instanceof PrewarmRequest preWarmRequest) {
			preWarmRequest.buildResponseTemplate();
			preWarmRequest.prewarmresponse.operationSupported = false;
		}
		else if (query instanceof PasswordChange passwordChangeRequest) {
			passwordChangeRequest.buildResponseTemplate();
			passwordChangeRequest.passwordResponse.changeSuccessful = false;
			passwordChangeRequest.passwordResponse.errorMessage =
				"Unsupported operation for H2 backend";
		}
		else if (query instanceof AdjustVectorIndex q) {
			q.buildResponseTemplate();
			q.adjustresponse.operationSupported = false;
		}
		else {
			return super.doQuery(query, c);
		}
		return query.getResponse();
	}

	@Override
	protected VectorResult queryVectorId(long id) throws SQLException {
		VectorResult rowres = vectorTable.queryVectorById(id);
		if (rowres == null) {
			throw new SQLException("Bad vector table rowid");
		}
		return rowres;
	}

	@Override
	protected long storeSignatureRecord(SignatureRecord sigrec) throws SQLException {
		// NOTE: ignore sigrec count - assume only one (1)
		return vectorTable.updateVector(sigrec.getLSHVector(), 1);
	}

	@Override
	protected int queryNearestVector(List<VectorResult> resultset, LSHVector vec,
		double simthresh, double sigthresh, int max) throws SQLException {
		VectorCompare comp;
		List<VectorResult> resultsToSort = new ArrayList<>();
		for (VectorStoreEntry entry : vectorStore) {
			if (entry.selfSig() < sigthresh) {
				continue;
			}
			vec.compare(entry.vec(), comp = new VectorCompare());
			double cosine = comp.dotproduct / (vec.getLength() * entry.vec().getLength());
			if (cosine <= simthresh) {
				continue;
			}
			double sig = vectorFactory.calculateSignificance(comp);
			if (sig <= sigthresh) {
				continue;
			}
			resultsToSort
				.add(new VectorResult(entry.id(), entry.count(), cosine, sig, entry.vec()));
		}
		resultsToSort.sort((r1, r2) -> Double.compare(r2.sim, r1.sim));
		int maxResults = Math.min(max, resultsToSort.size());
		for (int i = 0; i < maxResults; ++i) {
			resultset.add(resultsToSort.get(i));
		}
		return resultset.size();
	}

	@Override
	protected void queryNearestVector(QueryNearestVector query) throws SQLException {
		ResponseNearestVector response = query.nearresponse;
		response.totalvec = 0;
		response.totalmatch = 0;
		response.uniquematch = 0;

		// Use really big vector limit if not specified
		int vectormax = query.vectormax == 0 ? 2000000 : query.vectormax;

		List<FunctionDescription> toQuery = getFuncsToQuery(query.manage, query.signifthresh);
		response.totalvec = toQuery.size();

		GThreadPool threadPool = GThreadPool.getSharedThreadPool(H2_THREADPOOL_NAME);
		ConcurrentQBuilder<FunctionDescription, SimilarityVectorResult> evalBuilder =
			new ConcurrentQBuilder<>();
		ConcurrentQ<FunctionDescription, SimilarityVectorResult> evalQ =
			evalBuilder.setThreadPool(threadPool)
				.setCollectResults(true)
				.setMonitor(TaskMonitor.DUMMY)
				.build((fd, m) -> {
					List<VectorResult> resultset = new ArrayList<>();
					queryNearestVector(resultset, fd.getSignatureRecord().getLSHVector(),
							query.thresh, query.signifthresh, vectormax);
					if (resultset.isEmpty()) {
						return null;
					}
					SimilarityVectorResult simres = new SimilarityVectorResult(fd);
					simres.addNotes(resultset);
					return simres;
				});

		evalQ.add(toQuery);
		try {
			Collection<QResult<FunctionDescription, SimilarityVectorResult>> results =
				evalQ.waitForResults();
			for (QResult<FunctionDescription, SimilarityVectorResult> result : results) {
				SimilarityVectorResult simres = result.getResult();
				if (simres == null) {
					continue;
				}
				response.totalmatch += simres.getTotalCount();
				if (simres.getTotalCount() == 1) {
					response.uniquematch += 1;
				}
				response.result.add(simres);
			}
		}
		catch (Exception e) {
			return; //shouldn't happen
		}
	}

	@Override
	public int queryFunctions(QueryNearest query, BSimSqlClause filter, ResponseNearest response,
		DescriptionManager descMgr, Iterator<FunctionDescription> iter)
		throws SQLException, LSHException {
		//TODO: is this what the method should return
		//TODO: why is iter an argument?  Why not just use query.manage.listAllFunctions()

		//build a QueryNearestVector from query to do the vector search in parallel

		QueryNearestVector qnv = new QueryNearestVector();
		qnv.manage.transferSettings(query.manage);
		qnv.signifthresh = query.signifthresh;
		qnv.thresh = query.thresh;
		qnv.vectormax = query.vectormax;
		qnv.buildResponseTemplate();

		//currently the parallelized vector search does no de-duping
		//so we compute the number of distinct vectors queried to return
		Set<Long> distinctVecIds = new HashSet<>();

		while (iter.hasNext()) {
			FunctionDescription fd = iter.next();
			if (fd.getSignatureRecord() != null) {
				distinctVecIds.add(fd.getSignatureRecord().getLSHVector().calcUniqueHash());
				qnv.manage.transferFunction(fd, true);
			}
		}
		queryNearestVector(qnv);
		ResponseNearestVector rnv = qnv.nearresponse;

		//seems fishy but agrees with AbstractSQLFunctionDatabase.queryFunctions
		response.totalfunc = rnv.totalvec;

		for (SimilarityVectorResult simVecRes : rnv.result) {
			FunctionDescription base = simVecRes.getBase();
			Iterator<VectorResult> vecResults = simVecRes.iterator();
			SimilarityResult sim = new SimilarityResult(base);
			sim.setTotalCount(simVecRes.getTotalCount());
			int funcsForVec = 0;
			while (vecResults.hasNext()) {
				if (funcsForVec >= query.max) {
					break;
				}
				VectorResult dresult = vecResults.next();
				funcsForVec +=
					retrieveFuncDescFromVectors(dresult, descMgr, funcsForVec, query, filter, sim);
			}
			if (sim.size() == 0) {
				continue;
			}
			response.totalmatch += 1;
			if (sim.size() == 1) {
				response.uniquematch += 1;
			}
			response.result.add(sim);
			sim.transfer(response.manage, true);
		}
		return distinctVecIds.size();
	}

	private List<FunctionDescription> getFuncsToQuery(DescriptionManager manager, double sigBound) {
		Iterator<FunctionDescription> iter = manager.listAllFunctions();
		List<FunctionDescription> toQuery = new ArrayList<>();
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
			if (len2 < sigBound) {
				continue;
			}
			toQuery.add(frec);
		}
		return toQuery;
	}

	@Override
	public String formatBitAndSQL(String v1, String v2) {
		return "BITAND(" + v1 + "," + v2 + ")";
	}

	@Override
	public int getQueriedFunctionsPerStage() {
		return QUERY_FUNCS_PER_STAGE;
	}

	@Override
	public int getOverviewFunctionsPerStage() {
		return OVERVIEW_FUNCS_PER_STAGE;
	}

}
