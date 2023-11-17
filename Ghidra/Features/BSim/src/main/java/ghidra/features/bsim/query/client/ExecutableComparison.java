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

import java.util.*;
import java.util.Map.Entry;

import generic.lsh.vector.LSHVector;
import generic.lsh.vector.LSHVectorFactory;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.client.tables.ExeTable.ExeTableOrderColumn;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.protocol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Compare an entire set of executables to each other by combining
 * significance scores between functions.  If individual functions
 * demonstrate multiple similarities, its score contributions are not
 * over counted, and the final scores are symmetric.  Scoring is efficient
 * because it iterates over the precomputed clusters of similar functions
 * in a BSim database.  The algorithm does divide and conquer based on
 * clusters of similar functions, which greatly improves efficiency over
 * full quadratic comparison of all functions. This can be further bounded
 * by putting a threshold on how close functions have to be to be considered
 * in the same cluster and on how many functions can be in a cluster before
 * ignoring their score contributions.
 */
public class ExecutableComparison {
	private FunctionDatabase database;			// Connection to the database
	private ExecutableScorer scorer;			// The scoring matrix and mapping to executables
	private String singleMd5;
	private TreeSet<Long> baseIds;				// Set of relevant vector ids
	private TreeSet<Long> queriedIds;			// Set of vector ids that have already been queried
	private LSHVectorFactory vectorFactory;		// Factory for computing significance scores
	private int hitCountThreshold;				// Threshold for functions within a single cluster
	private int maxHitCount;					// Maximum hitcount seen (after performScoring)
	private int exceedCount;					// Number of times hitCountThreshold was exceeded
	private TaskMonitor monitor;				// Monitor for long running jobs

	/**
	 * Mutable integer class for histogram
	 */
	static public class Count {
		public int value = 0;
	}

	/**
	 * Initialize a comparison object with an active connection and thresholds, using the matrix scorer
	 * @param database is the active connection to a BSim database
	 * @param hitCountThreshold is the maximum number of functions to consider in one cluster
	 * @param monitor is a monitor to provide progress and cancellation checks
	 * @throws LSHException if the database connection is not established
	 */
	public ExecutableComparison(FunctionDatabase database, int hitCountThreshold,
		TaskMonitor monitor) throws LSHException {
		this.database = database;
		this.singleMd5 = null;
		this.hitCountThreshold = hitCountThreshold;
		this.monitor = monitor;
		if (this.monitor == null) {
			this.monitor = TaskMonitor.DUMMY;
		}
		baseIds = null;
		queriedIds = null;
		DatabaseInformation info = pullConnectionInfo();
		scorer = new ExecutableScorer();		// The matrix scorer, everybody compared to everybody
		scorer.transferSettings(info);
	}

	/**
	 * Initialize a comparison object with an active connection and thresholds, using the row scorer
	 * @param database is the active connection to a BSim database
	 * @param hitCountThreshold is the maximum number of functions to consider in one cluster
	 * @param md5 is the 32-character md5 string of the executable to single out for comparison
	 * @param cache holds the self-scores or is null if normalized scores aren't needed
	 * @param monitor is a monitor to provide progress and cancellation checks
	 * @throws LSHException if the database connection is not established
	 */
	public ExecutableComparison(FunctionDatabase database, int hitCountThreshold, String md5,
		ScoreCaching cache, TaskMonitor monitor) throws LSHException {
		this.database = database;
		this.singleMd5 = md5;
		this.hitCountThreshold = hitCountThreshold;
		this.monitor = monitor;
		if (this.monitor == null) {
			this.monitor = TaskMonitor.DUMMY;
		}
		baseIds = null;
		queriedIds = null;
		DatabaseInformation info = pullConnectionInfo();
		scorer = new ExecutableScorerSingle(cache);		// The row scorer, compare single exe to everybody else
		scorer.transferSettings(info);
		addExecutable(singleMd5);
	}

	/**
	 * @return maximum hit count seen for a cluster
	 */
	public int getMaxHitCount() {
		return maxHitCount;
	}

	/**
	 * @return number of clusters that exceeded hitCountThreshold
	 */
	public int getExceedCount() {
		return exceedCount;
	}

	/**
	 * @return true if similarity and significance thresholds have been set
	 */
	public boolean isConfigured() {
		return (scorer.simThreshold > 0.0);
	}

	/**
	 * Make sure the database has an active connection. Query for basic
	 * information and inform the scorer of settings
	 * @return information from the database
	 * @throws LSHException if something is wrong with the connection
	 */
	private DatabaseInformation pullConnectionInfo() throws LSHException {
		if (!database.initialize()) {
			throw new LSHException("Unable to connect to server");
		}
		QueryInfo query = new QueryInfo();
		ResponseInfo response = query.execute(database);
		if (response == null) {
			throw new LSHException(database.getLastError().message);
		}
		vectorFactory = database.getLSHVectorFactory();
		return response.info;
	}

	/**
	 * Look up a full ExecutableRecord in the database given an md5
	 * @param md5 is the md5 String
	 * @return the corresponding ExecutableRecord
	 * @throws LSHException if there are problems accessing the database
	 *    or the executable doesn't exist
	 */
	private ExecutableRecord lookupExecutable(String md5) throws LSHException {
		QueryName query = new QueryName();
		query.spec = new ExeSpecifier();
		query.spec.exemd5 = md5;
		query.maxfunc = 1;
		query.fillinCallgraph = false;
		query.fillinCategories = false;
		query.fillinSigs = false;
		ResponseName response = query.execute(database);
		if (response == null) {
			throw new LSHException(database.getLastError().message);
		}
		if (response.manage.numExecutables() != 1) {
			throw new LSHException("Could not find executable");
		}
		return response.manage.getExecutableRecordSet().first();
	}

	/**
	 * Query for all the vector ids associated with a specific executable.
	 * Store them in the vectorMap
	 * @param exeSpec indicates the specific executable
	 * @param histogram is non-null, provide a histogram of the vector ids
	 */
	private void pullVectorsForExe(ExeSpecifier exeSpec, Map<Long, Count> histogram) {
		QueryName queryName = new QueryName();
		queryName.spec = exeSpec;
		// TODO: Need to make more of an effort to collect all vectors for large executables.
		// But, this requires a change to the QueryName API to allow a window to be specified
		queryName.maxfunc = 100000;
		queryName.fillinCallgraph = false;
		queryName.fillinCategories = false;
		queryName.fillinSigs = false;

		ResponseName response = queryName.execute(database);
		Iterator<FunctionDescription> iter = response.manage.listAllFunctions();
		if (histogram == null) {
			while (iter.hasNext()) {
				baseIds.add(iter.next().getVectorId());
			}
		}
		else {
			while (iter.hasNext()) {
				Long id = iter.next().getVectorId();
				Count count = histogram.computeIfAbsent(id, key -> new Count());
				count.value += 1;
			}
		}
	}

	/**
	 * Given a set of executables established for scoring, load all
	 * of the associated vector ids into -vectorMap-
	 * @throws CancelledException if something trips the monitor
	 */
	private void pullVectorsForScoringSet() throws CancelledException {
		baseIds = new TreeSet<Long>();
		queriedIds = new TreeSet<Long>();
		if (scorer instanceof ExecutableScorerSingle) {		// If we are doing single exe version
			ExeSpecifier specifier = new ExeSpecifier();
			specifier.exemd5 = singleMd5;
			pullVectorsForExe(specifier, null);				//   only pull vectors for the one executable
			return;
		}
		monitor.setMessage("Accumulating vector ids");
		TreeSet<ExecutableRecord> recordSet = scorer.executableSet.getExecutableRecordSet();
		monitor.initialize(recordSet.size());
		ExeSpecifier specifier = new ExeSpecifier();
		for (ExecutableRecord exeRecord : recordSet) {
			specifier.exemd5 = exeRecord.getMd5();
			pullVectorsForExe(specifier, null);
			monitor.checkCancelled();
			monitor.incrementProgress(1);
		}
	}

	/**
	 * Build a QueryNearestVector object for querying a single vector.
	 * This currently involves building a temporary "function" to hold the vector
	 * @param vector is the LSHVector to prepare the query for
	 * @param threshold defines how similar "close" vectors are
	 * @return the QueryNearestVector object
	 * @throws LSHException if (impossibly) there are problems creating the query object
	 */
	private QueryNearestVector buildVectorQuery(LSHVector vector, double threshold)
		throws LSHException {
		QueryNearestVector query = new QueryNearestVector();

		ExecutableRecord exeRecord = query.manage.newExecutableRecord(
			"bbbbaaaabbbbaaaabbbbaaaabbbbaaaa", null, null, null, null, null, null, null);
		FunctionDescription function =
			query.manage.newFunctionDescription("tmp", 0x1000L, exeRecord);
		SignatureRecord signature = query.manage.newSignature(vector, 1);
		query.manage.attachSignature(function, signature);

		query.manage.transferSettings(scorer.executableSet);
		query.thresh = threshold;
		return query;
	}

	/**
	 * Look up a single vector by id
	 * @param id is the Long id of the vector
	 * @return the matching vector result
	 * @throws LSHException if the vector does not exist
	 */
	private VectorResult buildSeedVector(Long id) throws LSHException {
		QueryVectorId query = new QueryVectorId();
		query.vectorIds.add(id);
		ResponseVectorId response = query.execute(database);
		if (response == null || response.vectorResults.size() != 1) {
			throw new LSHException("Could not locate vector by id");
		}
		return response.vectorResults.get(0);
	}

	/**
	 * Pull one ID out of the workList, look-up its corresponding vector, and query for nearby vectors.
	 * Add IDs of the close vectors (that have not been seen before) to the workList
	 * Use vectorMap to keep track of what's been seen/queried before
	 * @param workList is the current list of IDs yet to be processed for the cluster
	 * @param threshold defines how similar "close" vectors are
	 * @return the VectorResult of the next ID
	 * @throws LSHException if something goes wrong during a query
	 */
	private VectorResult queryVectorForCluster(TreeMap<Long, VectorResult> workList,
		double threshold)
		throws LSHException {
		Entry<Long, VectorResult> entry = workList.pollFirstEntry();
		VectorResult currentVector = entry.getValue();
		baseIds.remove(entry.getKey());		// Look-up vector and remove from to-do list
		queriedIds.add(entry.getKey());		// Mark that this id has been queried
		if (currentVector == null) {
			currentVector = buildSeedVector(entry.getKey());	// If VectorResult isn't present, this must be a seed for the cluster
		}
		QueryNearestVector query = buildVectorQuery(currentVector.vec, threshold);
		ResponseNearestVector response = query.execute(database);
		if (response == null || response.result.size() != 1) {
			throw new LSHException("Could not perform query on vector");
		}
		Iterator<VectorResult> iter = response.result.get(0).iterator();
		while (iter.hasNext()) {
			VectorResult vecResult = iter.next();
			Long curId = vecResult.vectorid;
			if (queriedIds.contains(curId)) {
				continue;	// Already queried
			}
			workList.put(curId, vecResult);
		}
		return currentVector;
	}

	/**
	 * Starting with the first vector in -vectorMap- build the cluster of vectors that are within
	 * a given -threshold- of each other. The cluster is the "connected" component containing the
	 * first vector, where two vectors are "connected" if they are similar to each other within
	 * the threshold. 
	 * @param cluster will hold the list of vectors in the cluster
	 * @param simThreshold is the similarity threshold defining "near" or "connected"
	 * @param sigThreshold is the minimum significance for contributing score 
	 * @return the total number of functions associated with any vector in the cluster
	 * @throws LSHException is something goes wrong during database queries
	 */
	private int buildCluster(List<VectorResult> cluster, double simThreshold,
		double sigThreshold)
		throws LSHException {
		TreeMap<Long, VectorResult> workList = new TreeMap<Long, VectorResult>();
		Long firstKey = baseIds.pollFirst();
		workList.put(firstKey, null);
		int hitCount = 0;
		while (!workList.isEmpty()) {
			VectorResult vectorInfo = queryVectorForCluster(workList, simThreshold);	// Retrieve vector, add close vectors
			if (sigThreshold < vectorFactory.getSelfSignificance(vectorInfo.vec)) {	// If self-sig exceeds threshold
				cluster.add(vectorInfo);											//    add it to the cluster
				hitCount += vectorInfo.hitcount;
			}
		}
		return hitCount;
	}

	/**
	 * For each vector in a list -cluster-, query the database and populate a
	 * container (DescriptionManager) with the functions associated with the vector.
	 * Return the list of containers
	 * with that vector
	 * @param cluster is the list of vectors
	 * @return the list of DescriptionManager containers
	 * @throws LSHException if anything goes wrong with queries
	 */
	private List<DescriptionManager> vectorToFunctions(List<VectorResult> cluster)
		throws LSHException {
		List<DescriptionManager> result = new ArrayList<DescriptionManager>(cluster.size());
		for (int i = 0; i < cluster.size(); ++i) {
			VectorResult vector = cluster.get(i);
			QueryVectorMatch query = new QueryVectorMatch();
			query.fillinCategories = false;
			query.max = vector.hitcount + 10;	// vector.hitcount should be exact, but set threshold slightly
												// higher so we can tell if we exceeded hitcount
			query.vectorIds.add(vector.vectorid);
			ResponseVectorMatch response = query.execute(database);
			if (response == null) {
				throw new LSHException(database.getLastError().message);
			}
//			if (response.manage.numFunctions() > vector.hitcount) {
//				throw new LSHException("Function count exceeds vector hitcount -- possible database corruption");
//			}
			scorer.labelAndFilter(response.manage);
			result.add(response.manage);
		}
		return result;
	}

	/**
	 * @return the ExecutableScorer to allow examination of scores
	 */
	public ExecutableScorer getScorer() {
		return scorer;
	}

	/**
	 * Register an executable to be scored
	 * @param md5 is the MD5 string of the executable
	 * @throws LSHException if the executable is not in the database
	 */
	public void addExecutable(String md5) throws LSHException {
		ExecutableRecord exeRecord = lookupExecutable(md5);
		scorer.addExecutable(exeRecord);
	}

	/**
	 * Add all executables currently in the database to this object for comparison.
	 * @param limit is the max number of executables to compare against (if greater than zero)
	 * @throws LSHException for problems retrieving ExecutableRecords from the database
	 */
	public void addAllExecutables(int limit) throws LSHException {
		QueryExeInfo query =
			new QueryExeInfo(limit, null, null, null, null, ExeTableOrderColumn.MD5, false);
		ResponseExe responseExe = query.execute(database);
		if (responseExe == null) {
			throw new LSHException(database.getLastError().message);
		}
		for (ExecutableRecord exeRecord : responseExe.records) {
			scorer.addExecutable(exeRecord);
		}
	}

	/**
	 * Perform scoring between all registered executables.
	 * @throws LSHException for any connection issues during the process
	 * @throws CancelledException if the monitor reports cancellation
	 */
	public void performScoring() throws LSHException, CancelledException {
		maxHitCount = 0;
		exceedCount = 0;
		scorer.populateExecutableIndex();
		if (singleMd5 != null) {
			scorer.setSingleExecutable(singleMd5);
		}
		pullVectorsForScoringSet();
		scorer.initializeScores();

		monitor.setMessage("Processing similar functions");
		int maxSize = baseIds.size();
		monitor.initialize(maxSize);
		if (scorer.simThreshold < 0.0) {
			throw new LSHException("No thresholds have been established");
		}
		while (!baseIds.isEmpty()) {
			List<VectorResult> vectors = new ArrayList<VectorResult>();
			int hitcount = buildCluster(vectors, scorer.simThreshold, scorer.sigThreshold);
			if (hitcount == 0) {	// Zero is possible, if all vectors in cluster are below sig threshold
				continue;
			}
			else if (hitcount > maxHitCount) {		// Keep track of biggest hitcount
				maxHitCount = hitcount;
			}
			if (!scorer.checkPreliminaryPairThreshold(hitcount, hitCountThreshold)) {		// Cluster is too big
				exceedCount += 1;					// Count the occurrence
				continue;							// Don't score with this cluster
			}
			List<DescriptionManager> vec2Functions = vectorToFunctions(vectors);
			if (!scorer.scoreCluster(vectorFactory, vec2Functions, vectors, hitcount,
				hitCountThreshold)) {
				exceedCount += 1;
				continue;
			}
			monitor.checkCancelled();
			monitor.setProgress(maxSize - baseIds.size());
		}
		baseIds = null;
		queriedIds = null;		// Release storage
	}

	/**
	 * Remove any old scores and set new thresholds for the scorer
	 * @param simThreshold is the similarity threshold for new scores
	 * @param sigThreshold is the significance threshold for new scores
	 * @throws LSHException if there are problems saving new thresholds
	 */
	public void resetThresholds(double simThreshold, double sigThreshold) throws LSHException {
		scorer.resetStorage(simThreshold, sigThreshold);
	}

	/**
	 * Generate any missing self-scores within the list of registered executables.
	 * @throws LSHException for problems retrieving vectors
	 * @throws CancelledException if the user clicks "cancel"
	 */
	public void fillinSelfScores() throws LSHException, CancelledException {
		if (!(scorer instanceof ExecutableScorerSingle)) {
			return;
		}
		ExecutableScorerSingle singleScorer = (ExecutableScorerSingle) scorer;
		List<ExecutableRecord> missing = new ArrayList<ExecutableRecord>();
		singleScorer.prefetchSelfScores(missing);
		int size = missing.size();
		if (size == 0) {
			return;
		}
		if (size == 1) {
			if (missing.get(0).getMd5().equals(singleMd5)) {
				return;
			}
		}

		double sigThreshold = singleScorer.getSigThreshold();
		monitor.setMessage("Generating self-significance scores");
		monitor.initialize(size);
		Iterator<ExecutableRecord> iter = missing.iterator();
		ExeSpecifier exeSpec = new ExeSpecifier();
		while (iter.hasNext()) {
			ExecutableRecord exeRec = iter.next();
			if (exeRec.getMd5().equals(singleMd5)) {			// Don't need to prefetch the singular executable
				continue;
			}
			TreeMap<Long, Count> histogram = new TreeMap<Long, Count>();
			exeSpec.exemd5 = exeRec.getMd5();
			pullVectorsForExe(exeSpec, histogram);
			double score = 0.0;
			Iterator<Entry<Long, Count>> histIter = histogram.entrySet().iterator();
			while (histIter.hasNext()) {
				Entry<Long, Count> entry = histIter.next();
				VectorResult vecResult = buildSeedVector(entry.getKey());
				double significance = vectorFactory.getSelfSignificance(vecResult.vec);
				if (significance < sigThreshold) {
					continue;
				}
				score += significance * entry.getValue().value;
			}
			scorer.commitSelfScore(exeRec.getMd5(), (float) score);
			monitor.checkCancelled();
			monitor.incrementProgress(1);
		}
	}
}
