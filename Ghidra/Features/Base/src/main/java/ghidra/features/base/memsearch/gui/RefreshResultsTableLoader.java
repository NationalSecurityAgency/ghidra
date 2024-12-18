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

import java.util.List;

import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.task.TaskMonitor;

/**
 * Table loader that reloads the table with existing results after refreshing the byte values in
 * those results.
 */
public class RefreshResultsTableLoader implements MemoryMatchTableLoader {

	private List<MemoryMatch> matches;
	private boolean hasResults;

	public RefreshResultsTableLoader(List<MemoryMatch> matches) {
		this.matches = matches;
	}

	@Override
	public void loadResults(Accumulator<MemoryMatch> accumulator, TaskMonitor monitor) {
		accumulator.addAll(matches);
		hasResults = !accumulator.isEmpty();
	}

	@Override
	public void dispose() {
		matches.clear();
		matches = null;
	}

	@Override
	public boolean didTerminateEarly() {
		return false;
	}

	@Override
	public MemoryMatch getFirstMatch() {
		return null;
	}

	@Override
	public boolean hasResults() {
		return hasResults;
	}
}
