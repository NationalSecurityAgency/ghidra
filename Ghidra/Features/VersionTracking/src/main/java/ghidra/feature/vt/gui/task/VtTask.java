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

import java.util.ArrayList;
import java.util.List;

import ghidra.feature.vt.api.main.VTSession;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public abstract class VtTask extends Task {
	private static final int MAX_ERRORS = 10;

	protected final VTSession session;

	private boolean success = false;
	private boolean cancelled = false;

	private List<Throwable> errors = new ArrayList<>();

	protected VtTask(String title, VTSession session) {
		super(title, true, true, true, true);
		this.session = session;
	}

	@Override
	public final void run(TaskMonitor monitor) {
		boolean restoreEvents = suspendEvents();

		try {
			success = doWork(monitor);
		}
		catch (CancelledException e) {
			cancelled = true;
		}
		catch (Exception e) {
			reportError(e);
		}
		finally {
			if (restoreEvents) {
				session.setEventsEnabled(true);
			}
		}
	}

	private boolean suspendEvents() {

		if (session == null) {
			return false; // no events to suspend
		}

		if (!shouldSuspendSessionEvents()) {
			return false; // this task has chosen not to suspend events
		}

		if (!session.isSendingEvents()) {
			return false; // someone external to this task is managing events
		}

		session.setEventsEnabled(false);
		return true;
	}

	/**
	 * Determine if session events should be suspended during task execution.
	 * This can improve performance during task execution at the expense of bulk
	 * table updates at task completion.  Method return false by default.
	 * If not constructed with a session this method is not used.
	 * @return true if events should be suspended
	 */
	protected boolean shouldSuspendSessionEvents() {
		return false;
	}

	protected abstract boolean doWork(TaskMonitor monitor) throws Exception;

	/**
	 * Returns true if this task was cancelled.
	 *
	 * @return true if this task was cancelled.
	 */
	public boolean wasCancelled() {
		return cancelled;
	}

	/**
	 * Returns true if the Task executed successfully.
	 *
	 * <P>Note: this method only makes sense if called after the task has executed.  If called
	 * before, it will always return false;
	 *
	 * @return true if the Task executed successfully.
	 */
	public boolean wasSuccessfull() {
		return success;
	}

	/**
	 * returns true if the task did not successfully complete due to an error
	 *
	 * @return true if the task did not successfully complete due to an error
	 */
	public boolean hasErrors() {
		return !errors.isEmpty();
	}

	public void showErrors() {
		if (errors.isEmpty()) {
			return;
		}

		String title = getErrorDialogTitle();
		String message = getErrorDetails();
		if (errors.size() == 1) {
			Msg.showError(this, null, title, message, errors.get(0));
			return;
		}

		Msg.showError(this, null, title, message);
	}

	protected String getErrorHeader() {
		return "Errors encountered for task \"" + getTaskTitle() + "\":";
	}

	private String getErrorDialogTitle() {
		if (success) {
			return "Task \"" + getTaskTitle() + "\" Partially Completed";
		}
		return "Task Failed: " + getTaskTitle();
	}

	/**
	 * Returns an HTML formated error message
	 * @return an HTML formatted error message
	 */
	public String getErrorDetails() {
		StringBuilder buf = new StringBuilder("<html>" + getErrorHeader());
		int errorCount = 0;
		buf.append("<blockquote><br>");
		for (Throwable t : errors) {

			String message = t.getMessage();
			if (message == null) {
				message = "Unexpected Exception: " + t.toString();
			}

			buf.append(message).append("<br>");
			if (++errorCount > MAX_ERRORS) {
				buf.append("...and " + (errors.size() - errorCount) + " more!");
				break;
			}
		}
		return buf.toString();
	}

	protected void reportError(Exception e) {
		Throwable t = e;
		Throwable cause = e.getCause();
		if (cause != null) {
			t = cause;
		}
		errors.add(t);
	}

	protected void addErrors(VtTask task) {
		errors.addAll(task.errors);
	}
}
