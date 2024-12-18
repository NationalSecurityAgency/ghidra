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

import java.util.*;

import docking.widgets.OptionDialog;
import ghidra.feature.vt.api.db.VTMatchSetDB;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.util.HelpLocation;
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

	private void removeMatches(TaskMonitor monitor) throws CancelledException {

		monitor.setMessage("Removing matches");
		int n = matches.size();
		monitor.initialize(n);

		//
		// First remove all matches that will not require user prompting (those that are not 
		// accepted or they are not the last match for a shared association).
		// 
		List<VTMatch> list = new ArrayList<>(matches); // create a mutable list
		Iterator<VTMatch> it = list.iterator();
		while (it.hasNext()) {
			monitor.checkCancelled();
			VTMatch match = it.next();
			VTMatchSetDB matchSet = (VTMatchSetDB) match.getMatchSet();
			if (matchSet.removeMatch(match)) {
				it.remove();
			}
			monitor.incrementProgress(1);
		}

		if (list.isEmpty()) {
			return;
		}

		//
		// Now we have to ask the user if they wish to remove applied matches.
		// 
		int delta = n - list.size();

		//@formatter:off
		String message = """
			Deleted %d of %d matches.
			
			The remaining %d matches are ACCEPTED.  Do you wish to delete these matches and
			leave any applied destination program markup in place?
			(Press F1 to see more help details)
			""".formatted(delta, n, list.size());
		//@formatter:on

		RemoveMatchDialog dialog = new RemoveMatchDialog(message);
		if (!dialog.promptToDelete()) {
			return;
		}

		it = list.iterator();
		while (it.hasNext()) {
			monitor.checkCancelled();
			VTMatch match = it.next();
			VTMatchSetDB matchSet = (VTMatchSetDB) match.getMatchSet();
			matchSet.deleteMatch(match);
			it.remove();
			monitor.incrementProgress(1);
		}
	}

	private class RemoveMatchDialog extends OptionDialog {

		RemoveMatchDialog(String message) {
			super("Delete ACCEPTED Matches?", message, "Delete Accepted Matches", "Finish",
				OptionDialog.QUESTION_MESSAGE, null, false);

			setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Remove_Match"));
		}

		boolean promptToDelete() {
			int choice = super.show();
			return choice == OptionDialog.OPTION_ONE; // "Delete Accepted Matches"
		}
	}
}
