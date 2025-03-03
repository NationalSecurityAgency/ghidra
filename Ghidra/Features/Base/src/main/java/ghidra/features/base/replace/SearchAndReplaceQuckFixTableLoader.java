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
package ghidra.features.base.replace;

import ghidra.features.base.quickfix.QuickFix;
import ghidra.features.base.quickfix.TableDataLoader;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Class for loading search and replace items into a ThreadedTableModel.
 */
public class SearchAndReplaceQuckFixTableLoader implements TableDataLoader<QuickFix> {

	private SearchAndReplaceQuery query;
	private Program program;
	private boolean hasResults;
	private boolean searchLimitExceeded;

	public SearchAndReplaceQuckFixTableLoader(Program program, SearchAndReplaceQuery query) {
		this.program = program;
		this.query = query;
	}

	@Override
	public void loadData(Accumulator<QuickFix> accumulator, TaskMonitor monitor)
			throws CancelledException {

		Accumulator<QuickFix> wrappedAccumulator =
			new SizeRestrictedAccumulatorWrapper<QuickFix>(accumulator, query.getSearchLimit());
		try {
			query.findAll(program, wrappedAccumulator, monitor);
		}
		catch (AccumulatorSizeException e) {
			searchLimitExceeded = true;
		}
		finally {
			hasResults = !accumulator.isEmpty();
		}
	}

	@Override
	public boolean didProduceData() {
		return hasResults;
	}

	@Override
	public boolean maxDataSizeReached() {
		return searchLimitExceeded;
	}
}
