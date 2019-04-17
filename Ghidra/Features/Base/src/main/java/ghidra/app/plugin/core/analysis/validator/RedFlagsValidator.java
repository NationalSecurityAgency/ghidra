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
package ghidra.app.plugin.core.analysis.validator;

import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.Iterator;

import docking.widgets.conditiontestpanel.ConditionResult;
import docking.widgets.conditiontestpanel.ConditionStatus;

public class RedFlagsValidator extends PostAnalysisValidator {
	private static final String NAME = "Red Flags Validator";

	public RedFlagsValidator(Program program) {
		super(program);
	}

	@Override
	public ConditionResult doRun(TaskMonitor monitor) {
		StringBuilder warnings = new StringBuilder();
		int flags = checkRedFlags(program, warnings, monitor);
		ConditionStatus status = flags > 0 ? ConditionStatus.Warning : ConditionStatus.Passed;
		return new ConditionResult(status, warnings.toString());
	}

	private int checkRedFlags(Program prog, StringBuilder warnings, TaskMonitor monitor) {
		Iterator<Bookmark> bookmarkIter = prog.getBookmarkManager().getBookmarksIterator("Error");
		int count = 0;
		monitor.setIndeterminate(true);
		while (bookmarkIter.hasNext() && !monitor.isCancelled()) {
			monitor.incrementProgress(1);
			bookmarkIter.next();
			count++;
		}
		if (count > 0) {
			warnings.append(prog.getDomainFile().getName() + " has " + count +
				" error bookmarks.\n");
		}
		return count;
	}

	@Override
	public String getDescription() {
		return "Look for red flags -- errors in disassembly, etc.";
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public String toString() {
		return getName();
	}
}
