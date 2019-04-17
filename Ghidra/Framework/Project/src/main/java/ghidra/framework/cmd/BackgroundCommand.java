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
package ghidra.framework.cmd;

import ghidra.framework.model.DomainObject;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Abstract command that will be run in a thread (in the background)
 * other than the AWT(GUI) thread.  Use this to apply a long running
 * command that is interruptable.
 * 
 * The monitor allows the command to display status information as it
 * executes.
 * 
 * This allows commands to make changes in the background so that the
 * GUI is not frozen and the user can still interact with the GUI.
 * 
 * 
 */
public abstract class BackgroundCommand implements Command {

	private String name;
	private boolean hasProgress;
	private boolean canCancel;
	private boolean isModal;
	private String statusMsg;

	public BackgroundCommand() {
		this("no-name", false, false, false);
	}

	public BackgroundCommand(String name, boolean hasProgress, boolean canCancel, boolean isModal) {
		this.name = name;
		this.hasProgress = hasProgress;
		this.canCancel = canCancel;
		this.isModal = isModal;
	}

	/*
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public final boolean applyTo(DomainObject obj) {
		return applyTo(obj, TaskMonitorAdapter.DUMMY_MONITOR);
	}

	/**
	 * Method called when this command is to apply changes to the
	 * given domain object.  A monitor is provided to display status
	 * information about the command as it executes in the background.
	 * 
	 * @param obj domain object that will be affected by the command
	 * @param monitor monitor to show progress of the command
	 * 
	 * @return true if the command applied successfully
	 */
	public abstract boolean applyTo(DomainObject obj, TaskMonitor monitor);

// TODO: This should really throw CancelledException when canceled

	@Override
	public String getName() {
		return name;
	}

	/**
	 * Check if the command provides progress information.
	 * 
	 * @return true if the command shows progress information
	 */
	public boolean hasProgress() {
		return hasProgress;
	}

	/**
	 * Check if the command can be canceled.
	 * 
	 * @return true if this command can be canceled
	 */
	public boolean canCancel() {
		return canCancel;
	}

	/**
	 * Check if the command requires the monitor to be modal.  No other
	 * command should be allowed, and the GUI will be locked.
	 * 
	 * @return true if no other operation should be going on while this
	 * command is in progress.
	 */
	public boolean isModal() {
		return isModal;
	}

	/**
	 * Called when this command is going to be removed/canceled without
	 * running it.  This gives the command the opportunity to free any
	 * temporary resources it has hold of.
	 */
	public void dispose() {
		// do nothing by default
	}

	/**
	 * Called when the task monitor is completely done with indicating progress.
	 */
	public void taskCompleted() {
		// do nothing by default
	}

	@Override
	public String getStatusMsg() {
		return statusMsg;
	}

	protected void setStatusMsg(String statusMsg) {
		this.statusMsg = statusMsg;
	}

	@Override
	public String toString() {
		return getName();
	}
}
