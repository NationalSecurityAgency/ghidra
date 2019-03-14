/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
import ghidra.framework.model.DomainObjectException;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Task to do a single search..
 * 
 */
class SearchTask extends Task {

	private Searcher textSearcher;
	private Navigatable navigatable;
	private ProgramLocation loc = null;
	private boolean isCanceled;
	private TaskMonitor taskMonitor;
	private Program program;

	/**
	 * Constructor for SearchTask.
	 * @param textSearcher existing search to use
	 * @param listener listener that will be called when the search
	 * completes
	 */
	SearchTask(Navigatable navigatable, Program program, Searcher textSearcher) {
		super("Searching Program Text", true, true, false);
		this.navigatable = navigatable;
		this.textSearcher = textSearcher;
		this.program = program;
	}

	/**
	 * @see ghidra.util.task.Task#run(TaskMonitor)
	 */
	@Override
	public void run(TaskMonitor monitor) {
		try {
			monitor.setMessage("Searching...");
			textSearcher.setMonitor(monitor);
			this.taskMonitor = monitor;
			if (isCanceled) {
				monitor.cancel();
			}
			else {
				loc = textSearcher.search();
			}
		}
		catch (Exception e) {
			if (!(e instanceof DomainObjectException)) {
				Msg.showError(this, null, "Error", "Error searching", e);
			}
		}
	}

	/**
	 * Get the text searcher that this task used.
	 */
	Searcher getTextSearcher() {
		return textSearcher;
	}

	/**
	 * Get the program for this search task.
	 */
	Navigatable getNavigatable() {
		return navigatable;
	}

	ProgramLocation getSearchLocation() {
		return loc;
	}

	/**
	 * Called when program is deactivated but the task hasn't started to
	 * run yet. Cancel it when it does run.
	 */
	public void cancel() {
		super.cancel();
		isCanceled = true;
	}

	public Program getProgram() {
		return program;
	}
}
