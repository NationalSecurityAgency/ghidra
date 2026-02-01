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

import ghidra.features.base.memsearch.matcher.SearchData;
import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.features.base.memsearch.searcher.MemorySearcher;
import ghidra.program.model.address.Address;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.task.TaskMonitor;

/**
 * Table loader for executing an incremental search forwards or backwards and adding that result
 * to the table.
 */
public class FindOnceTableLoader implements MemoryMatchTableLoader {

	private MemorySearcher<SearchData> searcher;
	private Address address;
	private List<MemoryMatch<SearchData>> previousResults;
	private MemorySearchResultsPanel panel;
	private MemoryMatch<SearchData> match;
	private boolean forward;

	public FindOnceTableLoader(MemorySearcher<SearchData> searcher, Address address,
			List<MemoryMatch<SearchData>> previousResults, MemorySearchResultsPanel panel,
			boolean forward) {
		this.searcher = searcher;
		this.address = address;
		this.previousResults = previousResults;
		this.panel = panel;
		this.forward = forward;
	}

	@Override
	public void loadResults(Accumulator<MemoryMatch<SearchData>> accumulator, TaskMonitor monitor) {
		accumulator.addAll(previousResults);

		match = searcher.findOnce(address, forward, monitor);

		if (match != null) {
			MemoryMatch<SearchData> existing = findExisingMatch(match.getAddress());
			if (existing != null) {
				existing.updateBytes(match.getBytes());
			}
			else {
				accumulator.add(match);
			}
		}
	}

	private MemoryMatch<SearchData> findExisingMatch(Address newMatchAddress) {
		for (MemoryMatch<SearchData> memoryMatch : previousResults) {
			if (newMatchAddress.equals(memoryMatch.getAddress())) {
				return memoryMatch;
			}
		}
		return null;
	}

	@Override
	public boolean didTerminateEarly() {
		return false;
	}

	@Override
	public MemoryMatch getFirstMatch() {
		return match;
	}

	@Override
	public void dispose() {
		previousResults = null;
	}

	@Override
	public boolean hasResults() {
		return match != null;
	}

}
