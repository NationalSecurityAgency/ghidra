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
package ghidra.framework.plugintool.mgr;

import java.rmi.ConnectException;

import db.TerminatedTransactionException;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.*;
import ghidra.util.Msg;
import ghidra.util.TaskUtilities;
import ghidra.util.exception.ClosedException;
import ghidra.util.exception.RollbackException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * A task that executes a command in separate thread, not in the Swing Thread
 */
class BackgroundCommandTask extends Task implements AbortedTransactionListener {

	private BackgroundCommand cmd;
	private ToolTaskManager taskMgr;
	private UndoableDomainObject obj;
	private TaskMonitor taskMonitor;

	private boolean doneQueueProcessing;

	/**
	 * Constructor
	 * 
	 * @param taskMgr manager for this background task.
	 * @param obj the domain object to be modified by this task.
	 * @param cmd the background command to invoke.
	 */
	public BackgroundCommandTask(ToolTaskManager taskMgr, UndoableDomainObject obj,
			BackgroundCommand cmd) {
		super(cmd.getName(), cmd.canCancel(), cmd.hasProgress(), cmd.isModal());
		this.cmd = cmd;
		this.taskMgr = taskMgr;
		this.obj = obj;
	}

	/**
	 * Returns the Domain Object associated with this Task
	 * @return the object
	 */
	public UndoableDomainObject getDomainObject() {
		return obj;
	}

	/**
	 * Returns command associated with this task
	 * 
	 * @return background command
	 */
	public BackgroundCommand getCommand() {
		return cmd;
	}

	@Override
	public void run(TaskMonitor monitor) {
		TaskUtilities.addTrackedTask(this, monitor);
		taskMonitor = monitor;
		int id;
		try {
			id = obj.startTransaction(cmd.getName(), this);
		}
		catch (Throwable t) {
			Msg.error(this, "Transaction error", t);
			monitor.cancel();
			synchronized (taskMgr) {
				doneQueueProcessing = true;
				taskMgr.clearTasks(obj);
				taskMgr.taskFailed(obj, cmd, monitor);
			}
			return;
		}
		finally {
			synchronized (taskMgr) {
				// Allow waiting task manager to continue once we have started the transaction
				taskMgr.notifyAll();
			}
		}

		boolean success = false;
		boolean commit = true;
		try {
			success = cmd.applyTo(obj, monitor);
			if (success) {
				taskMgr.taskCompleted(obj, this, monitor);
			}
		}
		catch (Throwable t) {
			synchronized (taskMgr) {
				doneQueueProcessing = true;
				taskMgr.clearQueuedCommands(obj);
			}

			if (t instanceof DomainObjectException) {
				t = t.getCause();
			}

			commit = shouldKeepData(t);

			if (isUnrecoverableException(t)) {
				monitor.cancel();
				taskMgr.clearTasks(obj);
				return;
			}
			else if (!(t instanceof RollbackException)) {
				String message =
					"An unexpected error occurred while processing the command: " + cmd.getName();
				Msg.showError(this, null, "Command Failure", message, t);
			}
		}
		finally {
			TaskUtilities.removeTrackedTask(this);
			try {
				obj.endTransaction(id, commit);
			}
			catch (DomainObjectException e) {
				Throwable cause = e.getCause();
				if (commit && !(cause instanceof ClosedException)) {
					Msg.error(this, "Transaction error", cause);
					success = false;
				}
			}
		}

		if (!success) {
			taskMgr.taskFailed(obj, cmd, monitor);
		}
	}

	private boolean shouldKeepData(Throwable t) {
		// unrecoverable exceptions are really bad; rollback exceptions signal to abort
		boolean reallyBad = isUnrecoverableException(t) || t instanceof RollbackException;
		return !reallyBad;
	}

	private boolean isUnrecoverableException(Throwable t) {

		//@formatter:off
		return t instanceof ConnectException ||
			   t instanceof TerminatedTransactionException ||
			   t instanceof DomainObjectLockedException ||
			   t instanceof ClosedException;
		//@formatter:on
	}

	@Override
	public void transactionAborted(long transactionID) {
		taskMonitor.cancel();
	}

	/**
	 * Mark this task as done queue processing.
	 */
	void setDoneQueueProcessing() {
		doneQueueProcessing = true;
	}

	/**
	 * @return true if task is still pending or actively processing and can
	 *         process new follow-on commands via the task manager.
	 */
	boolean isDoneQueueProcessing() {
		return doneQueueProcessing;
	}

}
