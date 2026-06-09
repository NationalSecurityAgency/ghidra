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
package ghidra.app.util.navigation;

import java.util.List;

import ghidra.app.services.QueryData;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Task for searching for symbols. All the logic for the search is done by the
 * {@link SymbolSearcher}.
 */
public class GoToSymbolSearchTask extends Task {

	private QueryData queryData;
	private List<Program> searchPrograms;
	private List<ProgramLocation> results;
	private int limit;

	public GoToSymbolSearchTask(QueryData queryData, List<Program> searchPrograms, int limit) {
		super("Searching Symbols...");
		this.queryData = queryData;
		this.searchPrograms = searchPrograms;
		this.limit = limit;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		SymbolSearcher searcher = new SymbolSearcher(queryData, limit, monitor);
		results = searcher.findMatchingSymbolLocations(searchPrograms);
	}

	public List<ProgramLocation> getResults() {
		return results;
	}

}
