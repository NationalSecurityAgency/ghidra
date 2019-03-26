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
package ghidra.program.util;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.RollbackException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Task for operating on programs. Will open and close a transaction around the
 * work.
 */
public abstract class ProgramTask extends Task {

	protected Program program;

	/**
	 * Construct a new Task that will operate on a program.
	 * 
	 * @param program the program that the task will operate on.
	 * @param title title the title associated with the task
	 * @param canCancel true means that the user can cancel the task
	 * @param hasProgress true means that the dialog should show a progress
	 *            indicator
	 * @param isModal true means that the dialog is modal and the task has to
	 *            complete or be canceled before any other action can occur
	 */
	protected ProgramTask(Program program, String title, boolean canCancel, boolean hasProgress,
			boolean isModal) {
		super(title, canCancel, hasProgress, isModal);
		this.program = program;
	}

	@Override
	public final void run(TaskMonitor monitor) {
		int transactionID = program.startTransaction(getTaskTitle());
		boolean doCommit = false;
		try {
			doRun(monitor);
			doCommit = true;
		}
		catch (RollbackException e) {
			Msg.error(this, "Task Failed - \"" + getTaskTitle() + "\"", e);
		}
		catch (Throwable t) {
			Msg.showError(this, null, "Task Failed - \"" + getTaskTitle() + "\"",
				"Task failed - \"" + getTaskTitle() + "\"", t);
		}
		finally {
			program.endTransaction(transactionID, doCommit);
		}
	}

	abstract protected void doRun(TaskMonitor monitor);
}
