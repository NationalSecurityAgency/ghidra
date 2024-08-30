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

import java.util.Iterator;

import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.features.base.memsearch.searcher.MemorySearcher;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.task.TaskMonitor;

/**
 * Table loader that performs a search and displays the results in the table.
 */
public class NewSearchTableLoader implements MemoryMatchTableLoader {

	private MemorySearcher memSearcher;
	private boolean completedSearch;
	private MemoryMatch firstMatch;

	NewSearchTableLoader(MemorySearcher memSearcher) {
		this.memSearcher = memSearcher;
	}

	@Override
	public void loadResults(Accumulator<MemoryMatch> accumulator, TaskMonitor monitor) {
		completedSearch = memSearcher.findAll(accumulator, monitor);
		Iterator<MemoryMatch> iterator = accumulator.iterator();
		if (iterator.hasNext()) {
			firstMatch = iterator.next();
		}
	}

	@Override
	public boolean didTerminateEarly() {
		return !completedSearch;
	}

	@Override
	public void dispose() {
		// nothing to do
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
