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

import java.util.Collection;
import java.util.List;

import ghidra.features.base.memsearch.combiner.Combiner;
import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.features.base.memsearch.searcher.MemorySearcher;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.task.TaskMonitor;

/**
 * Table loader that performs a search and then combines the new results with existing results.
 */
public class CombinedMatchTableLoader implements MemoryMatchTableLoader {
	private MemorySearcher memSearcher;
	private List<MemoryMatch> previousResults;
	private Combiner combiner;
	private boolean completedSearch;
	private MemoryMatch firstMatch;

	public CombinedMatchTableLoader(MemorySearcher memSearcher,
			List<MemoryMatch> previousResults, Combiner combiner) {
		this.memSearcher = memSearcher;
		this.previousResults = previousResults;
		this.combiner = combiner;
	}

	@Override
	public void loadResults(Accumulator<MemoryMatch> accumulator, TaskMonitor monitor) {
		ListAccumulator<MemoryMatch> listAccumulator = new ListAccumulator<>();
		completedSearch = memSearcher.findAll(listAccumulator, monitor);
		List<MemoryMatch> followOnResults = listAccumulator.asList();
		firstMatch = followOnResults.isEmpty() ? null : followOnResults.get(0);
		Collection<MemoryMatch> results = combiner.combine(previousResults, followOnResults);
		accumulator.addAll(results);
	}

	@Override
	public boolean didTerminateEarly() {
		return !completedSearch;
	}

	@Override
	public void dispose() {
		previousResults = null;
	}

	@Override
	public MemoryMatch getFirstMatch() {
		return firstMatch;
	}

	@Override
	public boolean hasResults() {
		return firstMatch != null;
	}

}
