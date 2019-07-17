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
package ghidra.util.search.memory;

import java.util.List;

import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class MemSearcherTask extends Task {

	private MemorySearchAlgorithm algorithm;
	private List<MemSearchResult> results;

	public MemSearcherTask(SearchInfo searchInfo, MemorySearchAlgorithm algorithm) {
		super("Search Memory", true, true, false);

		this.algorithm = algorithm;
		addTaskListener(searchInfo.getListener());
	}

	@Override
	public void run(TaskMonitor monitor) {

		ListAccumulator<MemSearchResult> accumulator = new ListAccumulator<>();
		algorithm.search(accumulator, monitor);
		this.results = accumulator.asList();
	}

	public List<MemSearchResult> getMatchingAddresses() {
		return results;
	}
}
