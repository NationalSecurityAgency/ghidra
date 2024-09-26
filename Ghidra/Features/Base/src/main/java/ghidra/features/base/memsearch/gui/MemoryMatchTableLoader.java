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
package ghidra.features.base.memsearch.gui;

import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.task.TaskMonitor;

/**
 * Interface for loading the memory search results table. Various implementations handle the
 * different cases such as a search all, or a search next, or combining results with a previous
 * search, etc.
 */
public interface MemoryMatchTableLoader {

	/**
	 * Called by the table model to initiate searching and loading using the threaded table models
	 * threading infrastructure.
	 * @param accumulator the accumulator to store results that will appear in the results table
	 * @param monitor the task monitor
	 */
	public void loadResults(Accumulator<MemoryMatch> accumulator, TaskMonitor monitor);

	/**
	 * Returns true if the search/loading did not fully complete. (Search limit reached, cancelled
	 * by user, etc.)
	 * @return true if the search/loading did not fully complete
	 */
	public boolean didTerminateEarly();

	/**
	 * Cleans up resources
	 */
	public void dispose();

	/**
	 * Returns the first match found. Typically used to navigate the associated navigatable.
	 * @return the first match found
	 */
	public MemoryMatch getFirstMatch();

	/**
	 * Returns true if at least one match was found.
	 * @return true if at least one match was found
	 */
	public boolean hasResults();
}
