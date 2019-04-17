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
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import java.util.List;

public class SetMarkupItemConsideredTask extends Task {

	protected final List<VTMarkupItem> markupItems;
	private final VTSessionDB session;
	protected final VTMarkupItemConsideredStatus status;

	public SetMarkupItemConsideredTask(VTSession session, List<VTMarkupItem> markupItems,
			VTMarkupItemConsideredStatus status) {
		this(status.name() + " Markup Items", session, markupItems, status);
	}

	protected SetMarkupItemConsideredTask(String title, VTSession session,
			List<VTMarkupItem> markupItems, VTMarkupItemConsideredStatus status) {
		super(title, true, true, true, true);
		this.markupItems = markupItems;

		if (!(session instanceof VTSessionDB)) {
			throw new IllegalArgumentException(
				"Unexpected condition - VTSession is not a DB object!");
		}

		this.session = (VTSessionDB) session;
		this.status = status;
	}

	@Override
	public void run(TaskMonitor monitor) {

		boolean commit = true;

		int matchSetTransactionID = session.startTransaction(getTaskTitle());
		try {
			doWork(monitor);
		}
		catch (CancelledException e) {
			commit = false;
		}
		catch (Exception e) {
			commit = false;
			Msg.showError(this, null, "Unable to Apply Markup Item(s)",
				"An unexpected error occurred attempting to apply markup item(s).", e);
		}
		finally {
			session.endTransaction(matchSetTransactionID, commit);
		}
	}

	protected void doWork(TaskMonitor monitor) throws Exception, CancelledException {
		monitor.initialize(markupItems.size());
		for (VTMarkupItem markupItem : markupItems) {
			monitor.checkCanceled();
			markupItem.setConsidered(status);
			monitor.incrementProgress(1);
		}
	}
}
