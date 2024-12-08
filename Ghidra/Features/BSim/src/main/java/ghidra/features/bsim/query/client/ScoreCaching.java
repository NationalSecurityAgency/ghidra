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

import java.util.List;
import java.util.Set;

import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.description.ExecutableRecord;

/**
 * Store and retrieve self-significance scores for executables specified by md5.
 * These are generally too expensive to compute on the fly, so this class
 * provides a persistence model for obtaining them.  These scores also depend
 * on specific threshold settings, so there is a method for checking the settings.
 */
public interface ScoreCaching {

	/**
	 * Pre-load self-scores for a set of executables.
	 * @param exeSet is the set of executables to check
	 * @param missing (optional - may be null) will contain the list of exes missing a score
	 * @throws LSHException if there are problems loading scores
	 */
	public void prefetchScores(Set<ExecutableRecord> exeSet, List<ExecutableRecord> missing)
			throws LSHException;

	/**
	 * Retrieve the self-significance score for a given executable
	 * @param md5 is the 32-character md5 string specifying the executable
	 * @return the corresponding score
	 * @throws LSHException if the score is not obtainable
	 */
	public float getSelfScore(String md5) throws LSHException;

	/**
	 * Commit a new self-significance score for an executable
	 * @param md5 is the 32-character md5 string specifying the executable
	 * @param score is the score to commit
	 * @throws LSHException if there's a problem saving the value
	 */
	public void commitSelfScore(String md5, float score) throws LSHException;

	/**
	 * @return similarity threshold configured with this cache
	 *          OR return -1 if the score is unconfigured
	 * @throws LSHException for problems retrieving configuration
	 */
	public double getSimThreshold() throws LSHException;

	/**
	 * @return significance threshold configured with this cache
	 *          OR return -1 if the score is unconfigured
	 * @throws LSHException for problems retrieving configuration
	 */
	public double getSigThreshold() throws LSHException;

	/**
	 * Clear out any existing scores, and reset to an empty database
	 * @param simThresh is new similarity threshold to associate with scores
	 * @param sigThresh is new significance threshold to associate with scores
	 * @throws LSHException if there is a problem modifying storage
	 */
	public void resetStorage(double simThresh, double sigThresh) throws LSHException;
}
