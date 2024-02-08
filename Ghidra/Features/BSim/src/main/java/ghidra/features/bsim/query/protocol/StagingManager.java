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
package ghidra.features.bsim.query.protocol;

import ghidra.features.bsim.query.LSHException;

/**
 * Abstract class for splitting up a (presumably large) query into smaller pieces
 * The object must be configured by a call to setQuery with details of the staged query
 * and then typically a call to setGlobalManager which specifies the data for the whole query
 * 
 * Placing the actual staged queries is accomplished by first calling initialize,
 * which establishes the first stage query, obtainable via the getQuery method.
 * Successive stage queries are built by calling nextStage repeatedly until it returns false.
 *
 */
public abstract class StagingManager {
	protected BSimQuery<?> globalQuery;	// The global query
	protected int totalsize;				// Total number of separate queries being staged
	protected int queriesmade;				// Number of queries currently sent

	public int getTotalSize() {
		return totalsize;
	}

	public int getQueriesMade() {
		return queriesmade;
	}

	/**
	 * Get the current staged query
	 * @return the QueryResponseRecord object
	 */
	public abstract BSimQuery<?> getQuery();

	/**
	 * Establish the first query stage
	 * @param q the query
	 * @return true if the initial query is constructed
	 * @throws LSHException if the initialization fails
	 */
	public abstract boolean initialize(BSimQuery<?> q) throws LSHException;

	/**
	 * Establish the next query stage
	 * @return true if a next query is constructed
	 * @throws LSHException if creating the new query fails 
	 */
	public abstract boolean nextStage() throws LSHException;
}
