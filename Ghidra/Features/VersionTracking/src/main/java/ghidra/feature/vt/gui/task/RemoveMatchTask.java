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
package ghidra.feature.vt.gui.task;

import java.util.List;

import ghidra.feature.vt.api.db.VTMatchSetDB;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class RemoveMatchTask extends VtTask {

	private final List<VTMatch> matches;

	public RemoveMatchTask(VTSession session, List<VTMatch> matches) {
		super("Remove Matches", session);
		this.matches = matches;
	}

	@Override
	protected boolean doWork(TaskMonitor monitor) throws Exception {
		removeMatches(monitor);
		return true;
	}

	private boolean removeMatches(TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Removing matches");
		monitor.initialize(matches.size());
		boolean failed = false;
		for (VTMatch match : matches) {
			monitor.checkCanceled();
			VTMatchSetDB matchSet = (VTMatchSetDB) match.getMatchSet();
			boolean matchRemoved = matchSet.removeMatch(match);
			if (!matchRemoved) {
				failed = true;
			}
			monitor.incrementProgress(1);
		}

		monitor.setProgress(matches.size());
		if (failed) {
			reportError("One or more of your matches could not be removed." +
				"\nNote: You can't remove a match if it is currently accepted.");
		}
		return true;
	}

}
