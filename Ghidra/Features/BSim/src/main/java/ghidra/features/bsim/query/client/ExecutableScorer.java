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

import generic.lsh.vector.LSHVectorFactory;
import generic.lsh.vector.VectorCompare;
import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.description.*;

/**
 * Class for accumulating a matrix of scores between pairs of executables
 * ExecutableRecords are registered with addExecutable. Scoring is accumulated
 * by repeatedly providing clusters of functions to scoreCluster.
 */
public class ExecutableScorer {
	/**
	 * Container for a pair of FunctionDescriptions, possibly from different DescriptionManagers
	 * along with similarity/significance information
	 */
	public static class FunctionPair implements Comparable<FunctionPair> {
		protected FunctionDescription funcA;
		protected FunctionDescription funcB;
		protected double similarity;
		protected double significance;

		public FunctionPair(FunctionDescription a, FunctionDescription b, double sim, double sig) {
			// For function pairs from the same two executables, make sure functions
			// from the same executable are consistently on the same side
			if (a.getExecutableRecord().getXrefIndex() <= b.getExecutableRecord().getXrefIndex()) {
				funcA = a;
				funcB = b;
			}
			else {
				funcA = b;
				funcB = a;
			}
			similarity = sim;
			significance = sig;
		}

		@Override
		public int compareTo(FunctionPair o) {
			int comp = Integer.compare(funcA.getExecutableRecord().getXrefIndex(),
				o.funcA.getExecutableRecord().getXrefIndex());
			if (comp != 0) {		// Compare first by side A executable
				return comp;
			}
			comp = Integer.compare(funcB.getExecutableRecord().getXrefIndex(),
				o.funcB.getExecutableRecord().getXrefIndex());
			if (comp != 0) {		// Compare second by side B executable
				return comp;
			}
			comp = Double.compare(similarity, o.similarity);
			if (comp != 0) {
				return -comp;		// Compare third by similarity, bigger comes earlier
			}
			comp = Long.compare(funcA.getAddress(), o.funcA.getAddress());
			if (comp != 0) {		// Compare fourth by address of side A function
				return comp;
			}
			comp = Long.compare(funcB.getAddress(), o.funcB.getAddress());
			return comp;			// Compare last by address of side B function
		}
	}

	protected DescriptionManager executableSet;			// Set of executables to compare
	protected Map<Integer, ExecutableRecord> index2ExeMap;	// Mapping from index to registered executable
	private float[][] score;							// Matrix of accumulated scores
	protected double simThreshold;						// Similarity threshold associated with scores
	protected double sigThreshold;						// Significance threshold associated with scores
	protected ExecutableRecord singleExe;				// singled out executable
	protected int singleExeXref;						// index of the singled out executable to filter on

	public ExecutableScorer() {
		executableSet = new DescriptionManager();
		score = null;
		index2ExeMap = null;
		singleExe = null;
		singleExeXref = -1;
		simThreshold = -1.0;
		sigThreshold = -1.0;
	}

	/**
	 * @return the similarity threshold associated with these scores
	 *    OR -1.0 if no threshold has been set
	 */
	public double getSimThreshold() {
		return simThreshold;
	}

	/**
	 * @return the significance threshold associated with these scores
	 */
	public double getSigThreshold() {
		return sigThreshold;
	}

	/**
	 * Set a single executable as focus to enable the single parameter getScore(int)
	 * @param md5 is the 32-character md5 hash of the executable single out
	 * @throws LSHException if we can't find the executable
	 */
	public void setSingleExecutable(String md5) throws LSHException {
		singleExe = executableSet.findExecutable(md5);
		singleExeXref = singleExe.getXrefIndex();		// Save the xref of the single
	}

	/**
	 * @return number of executable self-significance scores are (will be) available
	 */
	public int countSelfScores() {
		return executableSet.numExecutables();
	}

	/**
	 * Clear any persistent storage for self-significance scores, and establish new thresholds
	 * @param simThresh is the new similarity threshold
	 * @param sigThresh is the new significance threshold
	 * @throws LSHException if there's a problem clearing storage
	 */
	public void resetStorage(double simThresh, double sigThresh) throws LSHException {
		simThreshold = simThresh;
		sigThreshold = sigThresh;
		score = null;				// Throw out any old scores
	}

	/**
	 * @return the number of executables being compared
	 */
	public int numExecutables() {
		return executableSet.numExecutables();
	}

	/**
	 * @return ExecutableRecord being singled out for comparison
	 */
	public ExecutableRecord getSingularExecutable() {
		return singleExe;
	}

	public float getSingularSelfScore() {
		return score[singleExeXref - 1][singleExeXref - 1];
	}

	/**
	 * Retrieve a specific ExecutableRecord by md5
	 * @param md5 is the MD5 string
	 * @return the matching ExecutableRecord
	 * @throws LSHException if the ExecutableRecord isn't present
	 */
	public ExecutableRecord getExecutable(String md5) throws LSHException {
		return executableSet.findExecutable(md5);
	}

	/**
	 * Get the index-th executable. NOTE: The first index is 1
	 * @param index of the executable to retrieve
	 * @return the ExecutableRecord describing the executable
	 */
	public ExecutableRecord getExecutable(int index) {
		if (index2ExeMap == null) {
			index2ExeMap = executableSet.generateExecutableXrefMap();
		}
		return index2ExeMap.get(index);
	}

	/**
	 * Save off information about database settings to inform later queries
	 * @param info is the information object returned by the database
	 */
	protected void transferSettings(DatabaseInformation info) {
		executableSet.setVersion(info.major, info.minor);
		executableSet.setSettings(info.settings);
	}

	/**
	 * Register an executable for the scoring matrix
	 * @param exeRecord is the ExecutableRecord to register
	 * @throws LSHException if the executable was already registered
	 *   with different metadata
	 */
	protected void addExecutable(ExecutableRecord exeRecord) throws LSHException {
		executableSet.transferExecutable(exeRecord);	// Transfer (re)sets xrefIndex to 0
	}

	/**
	 * Assuming all executables have been registered, establish index values
	 * for all executables to facilitate accessing the scoring matrix
	 */
	protected void populateExecutableIndex() {
		executableSet.populateExecutableXref();
	}

	/**
	 * For every executable in the container -manage-, if the executable
	 * matches up with a registered executable, set its xref index to match
	 * the registered executables xref index, otherwise set it to zero
	 * to indicate the executable should be filtered
	 * @param manage is the container of ExecutableRecords to label
	 */
	protected void labelAndFilter(DescriptionManager manage) {
		manage.matchAndSetXrefs(executableSet);
	}

	/**
	 * Initialize the scoring matrix with zero. The matrix size
	 * is the number of executables registered with addExecutable()
	 */
	protected void initializeScores() {
		int size = executableSet.numExecutables();
		score = new float[size][];
		for (int i = 0; i < size; ++i) {
			score[i] = new float[i + 1];
			float row[] = score[i];
			for (int j = 0; j <= i; ++j) {
				row[j] = 0.0f;
			}
		}
	}

	/**
	 * Given a pair of score contributing functions that have been
	 * fully filtered, add the score into the matrix
	 * @param pair is the pair of functions
	 */
	protected void scorePair(FunctionPair pair) {
		int indexA = pair.funcA.getExecutableRecord().getXrefIndex();
		int indexB = pair.funcB.getExecutableRecord().getXrefIndex();

		if (indexB > indexA) {
			int tmp = indexA;
			indexA = indexB;
			indexB = tmp;
		}
		score[indexA - 1][indexB - 1] += pair.significance;
	}

	/**
	 * Return the similarity score between two executables
	 * @param a is the index matching getXrefIndex() of the first executable
	 * @param b is the index matching getXrefIndex() of the second executable
	 * @return the similarity score
	 */
	public float getScore(int a, int b) {
		if (b > a) {
			int tmp = a;
			a = b;
			b = tmp;
		}
		return score[a - 1][b - 1];
	}

	/**
	 * Retrieve the similarity score of an executable with itself
	 * @param a is the index of the executable
	 * @return its self-similarity score
	 * @throws LSHException if the score is not accessible
	 */
	public float getSelfScore(int a) throws LSHException {
		return score[a - 1][a - 1];
	}

	/**
	 * Commit the singled out executables self-significance score to permanent storage
	 * @throws LSHException if there's a problem writing, or the operation isn't supported
	 */
	public void commitSelfScore() throws LSHException {
		throw new LSHException("Cannot commit self-score with the matrix scorer");
	}

	/**
	 * Commit a self-significance score for a specific executable to permanent storage
	 * @param md5 is the 32-character md5 hash of the executable
	 * @param selfScore is the self-significance score
	 * @throws LSHException if there's a problem writing, or the operation isn't supported
	 */
	protected void commitSelfScore(String md5, float selfScore) throws LSHException {
		throw new LSHException("Cannot commit self-score with the matrix scorer");
	}

	/**
	 * Get score of executable (as compared to our singled out executable)
	 * @param a is the index of the executable
	 * @return the score
	 */
	public float getScore(int a) {
		return getScore(singleExeXref, a);
	}

	/**
	 * Computes a score comparing two executables, normalized between 0.0 and 1.0,
	 * indicating the percentage of functional similarity between the two.
	 * 1.0 means "identical" 0.0 means completely "dissimilar"
	 * @param a is the index of the first executable
	 * @param b is the index of the second executable
	 * @param useLibrary is true if the score measures percent "containment"
	 *          of the smaller executable in the larger.
	 * @return the normalized score
	 * @throws LSHException if the self-scores for either executable are not available
	 */
	public float getNormalizedScore(int a, int b, boolean useLibrary) throws LSHException {
		float baseScore = getScore(a, b);
		float selfA = getSelfScore(a);
		float selfB = getSelfScore(b);
		// If selfA is bigger use selfB for library, selfA otherwise
		if (selfA < selfB) {			// If selfB is bigger
			useLibrary = !useLibrary;	//    flip this
		}
		if (useLibrary) {
			if (selfB == 0.0f) {
				return -1.0f;
			}
			return baseScore / selfB;
		}
		if (selfA == 0.0) {
			return -1.0f;
		}
		return baseScore / selfA;
	}

	public float getNormalizedScore(int a, boolean useLibrary) throws LSHException {
		return getNormalizedScore(a, singleExeXref, useLibrary);
	}

	/**
	 * Generate all pairs of functions for any function associated with a list of vectors
	 * For each pair of functions generate the FunctionPair object with corresponding
	 * similarity and significance.  This is inherently quadratic, but we try to be efficient.
	 * Duplicate vector pairs are only compared once and the similarity cached,
	 * and each function pair is generated only once, ie.  (funcA,funcB)  but not (funcB,funcA)
	 * @param vectorFactory provides weights for significance scores
	 * @param vec2func is the list of FunctionDescription sets associated with each vector
	 * @param vectors is the list of vectors
	 * @param hitcount is the cumulative total of functions
	 * @param pairThreshold is the maximum number of pairs that can be produced
	 * @return the array of FunctionPairs or null if pairThreshold is exceeded
	 */
	protected List<FunctionPair> pairFunctions(LSHVectorFactory vectorFactory,
		List<DescriptionManager> vec2func, List<VectorResult> vectors, int hitcount,
		int pairThreshold) {
		int totalSize = hitcount * (hitcount + 1) / 2;
		if (totalSize > pairThreshold) {
			return null;
		}
		List<FunctionPair> result = new ArrayList<FunctionPair>(totalSize);
		VectorCompare vectorCompare = new VectorCompare();
		for (int v1 = 0; v1 < vec2func.size(); ++v1) {
			for (int v2 = v1; v2 < vec2func.size(); ++v2) {
				double similarity = vectors.get(v1).vec.compare(vectors.get(v2).vec, vectorCompare);
				if (similarity < simThreshold) {
					continue;
				}
				double significance = vectorFactory.calculateSignificance(vectorCompare);
				if (significance < sigThreshold) {
					continue;
				}
				if (v1 == v2) {
					Iterator<FunctionDescription> iter1 = vec2func.get(v1).listAllFunctions();
					while (iter1.hasNext()) {
						FunctionDescription func1 = iter1.next();
						int func1Index = func1.getExecutableRecord().getXrefIndex();
						if (func1Index == 0) {
							continue;			// Executable is not in our scoring set
						}
						FunctionDescription func2;
						Iterator<FunctionDescription> iter2 = vec2func.get(v1).listAllFunctions();
						do {
							func2 = iter2.next();
							int func2Index = func2.getExecutableRecord().getXrefIndex();
							if (func2Index == 0) {
								continue;		// Executable is not in our scoring set
							}
							result.add(new FunctionPair(func1, func2, similarity, significance));
						}
						while (func2 != func1);
					}
				}
				else {
					Iterator<FunctionDescription> iter1 = vec2func.get(v1).listAllFunctions();
					while (iter1.hasNext()) {
						FunctionDescription func1 = iter1.next();
						int func1Index = func1.getExecutableRecord().getXrefIndex();
						if (func1Index == 0) {
							continue;			// Executable is not in our scoring set
						}
						Iterator<FunctionDescription> iter2 = vec2func.get(v2).listAllFunctions();
						while (iter2.hasNext()) {
							FunctionDescription func2 = iter2.next();
							int func2Index = func2.getExecutableRecord().getXrefIndex();
							if (func2Index == 0) {
								continue;		// Executable is not in our scoring set
							}
							result.add(new FunctionPair(func1, func2, similarity, significance));
						}
					}
				}
			}
		}
		return result;
	}

	/**
	 * For function pairs between the same two executables, do the final filtering
	 * to create symmetric score contributions and accumulate the contributions in the matrix
	 * @param pairs is the full list of pairs in the cluster
	 * @param i is the first function pair sharing this pair of executables
	 * @param j is the the last(+1) function pair sharing this pair of executables
	 */
	private void scoreAcrossExecutablePair(List<FunctionPair> pairs, int i, int j) {
		int size = j - i;
		FunctionPair pair1 = pairs.get(i);
		if (size == 1) {				// If only one pair between the two executable
			scorePair(pair1);			// we can score it immediately
		}
		else if (size == 2) {			// If there are two pairs between the two executables
			FunctionPair pair2 = pairs.get(i + 1);
			if (pair1.funcA == pair2.funcA || pair1.funcB == pair2.funcB) {		// If there is a function in common
				scorePair(pair1);												// only score one of the pairs
			}
			else {
				scorePair(pair1);												// otherwise we can score both pairs
				scorePair(pair2);
			}
		}
		else if (pair1.funcA.getExecutableRecord()
			.getXrefIndex() == pair1.funcB.getExecutableRecord().getXrefIndex()) {
			// Pairs coming from the same executable
			for (; i < j; ++i) {
				FunctionPair pair = pairs.get(i);
				if (pair.funcA == pair.funcB) {				// Only score function paired with itself
					scorePair(pair);
				}
			}
		}
		else {
			HashSet<Long> aUsed = new HashSet<Long>();		// Each function can be score only once (for these executables)
			HashSet<Long> bUsed = new HashSet<Long>();		// Keep track of which functions are used
			for (; i < j; ++i) {									// Run through the pairs (highest similarity first)
				FunctionPair pair = pairs.get(i);
				Long aAddress = pair.funcA.getAddress();
				if (aUsed.contains(aAddress)) {				// If the left-side function has been used before
					continue;								// skip this pair
				}
				Long bAddress = pair.funcB.getAddress();
				if (bUsed.contains(bAddress)) {				// If the right-side function has been used before
					continue;								// skip this pair
				}
				aUsed.add(aAddress);						// Mark the two functions as used
				bUsed.add(bAddress);
				scorePair(pair);
			}
		}
	}

	/**
	 * Make check if we are going to have too many pairs.
	 * This is preliminary because we haven't yet fetched the functions
	 * @param hitcount is the total number of pairs to fetch
	 * @param pairThreshold is the maximum number of pairs allowed
	 * @return true if the pair threshold is not exceeded
	 */
	protected boolean checkPreliminaryPairThreshold(int hitcount, int pairThreshold) {
		int totalSize = hitcount * (hitcount + 1) / 2;
		return (totalSize <= pairThreshold);
	}

	/**
	 * Given a cluster of vectors, the set of functions associated with each vector,
	 * a similarity threshold, and total number of functions in the cluster,
	 * let each pair of function contribute to the score matrix
	 * @param vectorFactory is a factory for computing significance scores
	 * @param vec2Functions is the list of sets of functions
	 * @param vectors is the list of vectors
	 * @param hitcount is the number of functions in the cluster
	 * @param pairThreshold is maximum number of pairs allowed
	 * @return true if the number of pairs was not exceeded
	 */
	protected boolean scoreCluster(LSHVectorFactory vectorFactory,
		List<DescriptionManager> vec2Functions, List<VectorResult> vectors,
		int hitcount, int pairThreshold) {
		List<FunctionPair> pairs =
			pairFunctions(vectorFactory, vec2Functions, vectors, hitcount, pairThreshold);
		if (pairs == null) {
			return false;
		}
		Collections.sort(pairs);
		int i = 0;
		while (i < pairs.size()) {
			ExecutableRecord rec1 = pairs.get(i).funcA.getExecutableRecord();
			ExecutableRecord rec2 = pairs.get(i).funcB.getExecutableRecord();
			int j = i + 1;
			while (j < pairs.size()) {
				FunctionPair currentPair = pairs.get(j);
				if (!rec2.equals(currentPair.funcB.getExecutableRecord()) ||
					!rec1.equals(currentPair.funcA.getExecutableRecord())) {
					break;
				}
				j += 1;
			}
			scoreAcrossExecutablePair(pairs, i, j);
			i = j;
		}
		return true;
	}
}
