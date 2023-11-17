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

import generic.lsh.vector.*;
import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.description.*;

/**
 * ExecutableComparison scorer to use when we are comparing exactly one executable
 * against a set of other executables (one to many).  We override the {@link ExecutableScorer}
 * (compare many to many) so that it effectively accesses only a single row
 * of the scoring matrix to get the "one to many" behavior we want.
 * The getNormalizedScore() methods on the base class require that executable self-scores,
 * other than the singled-out executable's self-score, be cached in some way.
 * Thus this scorer needs a {@link ScoreCaching} class.
 */
public class ExecutableScorerSingle extends ExecutableScorer {

	private float singleScore[];		// Score of single against all other executables
	private ScoreCaching scoreCache;

	/**
	 * Construct the scorer.  If normalized scores are required, a self-score cacher
	 * must be provided.
	 * @param cache is the self-score cacher or null
	 * @throws LSHException for problems initializing the cache
	 */
	public ExecutableScorerSingle(ScoreCaching cache) throws LSHException {
		super();						// Turn on single executable filtering
		singleScore = null;
		scoreCache = cache;
		if (scoreCache == null) {
			scoreCache = new TemporaryScoreCaching();
		}
		simThreshold = scoreCache.getSimThreshold();
		sigThreshold = scoreCache.getSigThreshold();
	}

	@Override
	public void setSingleExecutable(String md5) throws LSHException {
		if (singleExeXref >= 0) {
			throw new LSHException("Cannot reset singled executable");
		}
		super.setSingleExecutable(md5);
	}

	@Override
	public int countSelfScores() {
		Iterator<ExecutableRecord> iter = executableSet.getExecutableRecordSet().iterator();
		int count = 0;
		while (iter.hasNext()) {
			ExecutableRecord exe = iter.next();
			try {
				scoreCache.getSelfScore(exe.getMd5());
				count += 1;
			}
			catch (LSHException e) {
				// Don't increment count
			}
		}
		return count;
	}

	@Override
	public void resetStorage(double simThresh, double sigThresh) throws LSHException {
		super.resetStorage(simThresh, sigThresh);
		singleScore = null;
		scoreCache.resetStorage(simThresh, sigThresh);
	}

	@Override
	public float getSingularSelfScore() {
		return singleScore[singleExeXref - 1];
	}

	@Override
	protected void initializeScores() {
		// We only allocate the one row corresponding to our single, not the whole matrix
		int size = executableSet.numExecutables();
		singleScore = new float[size];
		for (int i = 0; i < size; ++i) {
			singleScore[i] = 0.0f;
		}
	}

	@Override
	protected boolean checkPreliminaryPairThreshold(int hitcount, int pairThreshold) {
		// Unless raw hit count exceeds threshold,
		// delay decision until we can see the functions by returning true
		return (hitcount < pairThreshold);
	}

	@Override
	protected void scorePair(FunctionPair pair) {
		int indexA = pair.funcA.getExecutableRecord().getXrefIndex();
		int indexB = pair.funcB.getExecutableRecord().getXrefIndex();

		if (indexA == singleExeXref) {
			singleScore[indexB - 1] += pair.significance;
		}
		else if (indexB == singleExeXref) {
			singleScore[indexA - 1] += pair.significance;
		}
	}

	@Override
	protected List<FunctionPair> pairFunctions(LSHVectorFactory vectorFactory,
		List<DescriptionManager> vec2func, List<VectorResult> vectors, int hitcount,
		int pairThreshold) {

		// Separate cluster into functions that are in singleExe
		// and functions that are NOT in singleExe  (but are still in our filter set)
		List<FunctionDescription> singleFuncs = new ArrayList<FunctionDescription>(hitcount);
		List<VectorResult> singleVec = new ArrayList<VectorResult>(hitcount);
		List<FunctionDescription> otherFuncs = new ArrayList<FunctionDescription>(hitcount);
		List<VectorResult> otherVec = new ArrayList<VectorResult>(hitcount);
		for (int i = 0; i < vec2func.size(); ++i) {
			DescriptionManager manage = vec2func.get(i);
			VectorResult curVec = vectors.get(i);
			Iterator<FunctionDescription> iter = manage.listAllFunctions();
			while (iter.hasNext()) {
				FunctionDescription func = iter.next();
				int xrefIndex = func.getExecutableRecord().getXrefIndex();
				if (xrefIndex == 0) {
					continue;						// Not in our filter set
				}
				else if (xrefIndex == singleExeXref) {
					singleFuncs.add(func);				// Save off function in singleExe for later enumeration
					singleVec.add(curVec);				// Save off its associated vector
				}
				else {
					otherFuncs.add(func);
					otherVec.add(curVec);
				}
			}
		}

		int pairCount = singleFuncs.size() * otherFuncs.size() +
			(singleFuncs.size() * (singleFuncs.size() + 1)) / 2;
		if (pairCount > pairThreshold) {
			return null;
		}
		// For each function (funcA) in singleExe
		//    a) enumerate pairs with funcA and other functions in singleExe
		//    b) enumerate pairs with funcA and other functions NOT in singleExe
		List<FunctionPair> pairs = new ArrayList<FunctionPair>(pairCount);
		VectorCompare vectorCompare = new VectorCompare();
		for (int i = 0; i < singleFuncs.size(); ++i) {
			FunctionDescription funcA = singleFuncs.get(i);
			LSHVector vectorA = singleVec.get(i).vec;
			LSHVector lastVec = vectorA;
			double similarity = 1.0;
			double significance = vectorFactory.getSelfSignificance(lastVec);

			// Create pairs from functions within singleExe
			for (int j = i; j < singleFuncs.size(); ++j) {
				LSHVector nextVec = singleVec.get(j).vec;
				if (lastVec != nextVec) {
					similarity = vectorA.compare(nextVec, vectorCompare);
					significance = vectorFactory.calculateSignificance(vectorCompare);
					lastVec = nextVec;
				}
				if (similarity < simThreshold || significance < sigThreshold) {
					continue;
				}
				pairs.add(new FunctionPair(funcA, singleFuncs.get(j), similarity, significance));
			}

			// Create pairs with one function in singleExe and one function not in singleExe
			for (int j = 0; j < otherFuncs.size(); ++j) {
				LSHVector nextVec = otherVec.get(j).vec;
				if (lastVec != nextVec) {
					similarity = vectorA.compare(nextVec, vectorCompare);
					significance = vectorFactory.calculateSignificance(vectorCompare);
					lastVec = nextVec;
				}
				if (similarity < simThreshold || significance < sigThreshold) {
					continue;
				}
				FunctionDescription funcB = otherFuncs.get(j);
				pairs.add(new FunctionPair(funcA, funcB, similarity, significance));
			}
		}

		return pairs;
	}

	@Override
	public float getScore(int a) {
		return singleScore[a - 1];
	}

	@Override
	public float getSelfScore(int a) throws LSHException {
		if (a == singleExeXref) {
			return singleScore[a - 1];
		}
		ExecutableRecord executableRecord = index2ExeMap.get(a);
		if (executableRecord == null) {
			return 0.0f;
		}
		return scoreCache.getSelfScore(executableRecord.getMd5());
	}

	@Override
	public void commitSelfScore() throws LSHException {
		scoreCache.commitSelfScore(singleExe.getMd5(), singleScore[singleExeXref - 1]);
	}

	@Override
	protected void commitSelfScore(String md5, float selfScore) throws LSHException {
		scoreCache.commitSelfScore(md5, selfScore);
	}

	@Override
	public float getScore(int a, int b) {
		// We use only the single column score matrix
		if (b == singleExeXref) {
			return singleScore[a - 1];
		}
		return singleScore[b - 1];

	}

	/**
	 * Pre-load self-scores of the registered executables.
	 * @param missing (optional - may be null) will contain the list of exes missing a score
	 * @throws LSHException if there are problems loading scores
	 */
	public void prefetchSelfScores(List<ExecutableRecord> missing)
		throws LSHException {
		scoreCache.prefetchScores(executableSet.getExecutableRecordSet(), missing);
	}
}
