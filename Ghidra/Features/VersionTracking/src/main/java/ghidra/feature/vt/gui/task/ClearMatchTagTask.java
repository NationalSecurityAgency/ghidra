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
package ghidra.feature.vt.gui.task;

import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import java.util.List;

public class ClearMatchTagTask extends Task {

	private VTSessionDB sessionDB;
	private List<VTMatch> matches;

	public ClearMatchTagTask(VTSession session, List<VTMatch> matches) {
		super("Clear Match Tag", true, true, true, true);
		this.matches = matches;

		if (!(session instanceof VTSessionDB)) {
			throw new IllegalArgumentException(
				"Unexpected condition - VTSession is not a DB object!");
		}

		this.sessionDB = (VTSessionDB) session;
	}

	@Override
	public void run(TaskMonitor monitor) {

		boolean commit = true;
		int matchSetTransactionID = sessionDB.startTransaction(getTaskTitle());
		try {
			doWork(monitor);
		}
		catch (CancelledException e) {
			commit = false;
		}
		finally {
			sessionDB.endTransaction(matchSetTransactionID, commit);
		}
	}

	protected void doWork(TaskMonitor monitor) throws CancelledException {
		monitor.initialize(matches.size());
		for (VTMatch match : matches) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			VTMatchTag tag = match.getTag();
			if (tag == VTMatchTag.UNTAGGED) {
				continue;
			}

			match.setTag(VTMatchTag.UNTAGGED);
		}
	}
}
