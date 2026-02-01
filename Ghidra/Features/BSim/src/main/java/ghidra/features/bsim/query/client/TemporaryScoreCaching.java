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

import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.description.ExecutableRecord;

/**
 * An in-memory score cacher.  It supports commitSelfScore() and getSelfScore()
 * calls, but the commits have no backing storage and vanish with each new instantiation
 * of this object. 
 */
public class TemporaryScoreCaching implements ScoreCaching {

	private TreeMap<String, Float> cacheMap;		// In memory cache of scores, indexed by md5 string
	private double simThreshold;				// similarity threshold loaded from file
	private double sigThreshold;				// significance threshold loaded from file

	public TemporaryScoreCaching() {
		cacheMap = null;
		simThreshold = -1.0;		// Negative indicates thresholds have not been configured
		sigThreshold = -1.0;
	}

	@Override
	public void prefetchScores(Set<ExecutableRecord> exeSet, List<ExecutableRecord> missing)
			throws LSHException {
		if (missing != null) {
			if (cacheMap == null) {
				for (ExecutableRecord exeRec : exeSet) {
					missing.add(exeRec);				// Everything is missing
				}
			}
			else {
				for (ExecutableRecord exeRec : exeSet) {
					if (!cacheMap.containsKey(exeRec.getMd5())) {
						missing.add(exeRec);
					}
				}
			}
		}
	}

	@Override
	public float getSelfScore(String md5) throws LSHException {
		if (cacheMap != null) {
			Float val = cacheMap.get(md5);
			if (val != null) {
				return val.floatValue();
			}
		}
		throw new LSHException("Self-score not recorded for " + md5);
	}

	@Override
	public void commitSelfScore(String md5, float score) throws LSHException {
		if (cacheMap == null) {
			cacheMap = new TreeMap<String, Float>();
		}
		cacheMap.put(md5, score);
	}

	@Override
	public double getSimThreshold() throws LSHException {
		return simThreshold;
	}

	@Override
	public double getSigThreshold() throws LSHException {
		return sigThreshold;
	}

	@Override
	public void resetStorage(double simThresh, double sigThresh) throws LSHException {
		cacheMap = null;
		simThreshold = simThresh;
		sigThreshold = sigThresh;
	}

}
