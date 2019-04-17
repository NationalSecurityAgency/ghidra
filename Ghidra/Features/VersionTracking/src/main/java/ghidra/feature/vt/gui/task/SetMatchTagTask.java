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

import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.framework.model.Transaction;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import java.util.List;

public class SetMatchTagTask extends Task {

	protected final List<VTMatch> matches;
	private final VTSessionDB sessionDB;
	private final VTMatchTag tag;

	public SetMatchTagTask(VTSession session, List<VTMatch> matches, VTMatchTag tag) {
		super("Set Match Tag", true, true, true, true);
		this.tag = tag;

		if (!(session instanceof VTSessionDB)) {
			throw new IllegalArgumentException(
				"Unexpected condition - VTSession is not a DB object!");
		}

		this.sessionDB = (VTSessionDB) session;
		this.matches = matches;
	}

	@Override
	public void run(TaskMonitor monitor) {

		if (hasTransactionsOpen()) {
			return;
		}

		boolean commit = true;
		int matchSetTransactionID = sessionDB.startTransaction(getTaskTitle());
		try {
			doWork(monitor);
		}
		catch (CancelledException e) {
			commit = false;
		}
		catch (Exception e) {
			commit = false;
			Msg.showError(this, null, "Unable to Set Match Tag",
				"An unexpected error occurred attempting to set match tag.", e);
		}
		finally {
			sessionDB.endTransaction(matchSetTransactionID, commit);
		}
	}

	private boolean hasTransactionsOpen() {
		Program program = sessionDB.getDestinationProgram();
		Transaction transaction = program.getCurrentTransaction();
		if (transaction != null) {
			Msg.showWarn(this, null, "Unable to Set Match Tag",
				"The program \"" + program.getName() + "\"already has a transaction open: " +
					transaction.getDescription());
			return true;
		}

		Transaction matchSetTransaction = sessionDB.getCurrentTransaction();
		if (matchSetTransaction != null) {
			Msg.showWarn(this, null, "Unable to Set Match Tag",
				"Transaction already open for the Match Set Manager ");
			return true;
		}
		return false;
	}

	protected void doWork(TaskMonitor monitor) throws Exception, CancelledException {
		monitor.initialize(matches.size());

		for (VTMatch match : matches) {
			monitor.checkCanceled();
			VTMatchTag currentTag = match.getTag();
			if (!currentTag.equals(tag)) {
				match.setTag(tag);
			}
			monitor.incrementProgress(1);
		}
	}
}
