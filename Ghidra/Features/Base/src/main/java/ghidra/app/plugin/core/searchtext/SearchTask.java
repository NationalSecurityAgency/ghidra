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
package ghidra.app.plugin.core.searchtext;

import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.searchtext.Searcher.TextSearchResult;
import ghidra.framework.model.DomainObjectException;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Task to do a single search.
 */
class SearchTask extends Task {

	private Searcher textSearcher;
	private Navigatable navigatable;
	private TextSearchResult result;
	private boolean isCanceled;
	private Program program;

	/**
	 * Constructor for SearchTask.
	 * @param navigatable the navigatable
	 * @param program the program
	 * @param textSearcher existing search to use
	 */
	SearchTask(Navigatable navigatable, Program program, Searcher textSearcher) {
		super("Searching Program Text", true, true, false);
		this.navigatable = navigatable;
		this.textSearcher = textSearcher;
		this.program = program;
	}

	@Override
	public void run(TaskMonitor monitor) {

		monitor.setMessage("Searching...");
		if (isCanceled) {
			monitor.cancel();
			return;
		}

		monitor.setMessage("Searching...");
		textSearcher.setMonitor(monitor);
		try {
			result = textSearcher.search();
		}
		catch (Exception e) {
			if (!(e instanceof DomainObjectException)) {
				Msg.showError(this, null, "Error", "Error searching", e);
			}
		}
	}

	Searcher getTextSearcher() {
		return textSearcher;
	}

	Navigatable getNavigatable() {
		return navigatable;
	}

	TextSearchResult getSearchLocation() {
		return result;
	}

	/**
	 * Called when program is deactivated but the task hasn't started to
	 * run yet. Cancel it when it does run.
	 */
	@Override
	public void cancel() {
		super.cancel();
		isCanceled = true;
	}

	public Program getProgram() {
		return program;
	}
}
