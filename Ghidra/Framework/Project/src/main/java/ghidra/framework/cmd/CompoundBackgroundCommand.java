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
package ghidra.framework.cmd;

import ghidra.framework.model.DomainObject;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;

/**
 * Compound command to handle multiple background commands.
 */
public class CompoundBackgroundCommand extends BackgroundCommand {

	private ArrayList<BackgroundCommand> bkgroundCmdList;
	private ArrayList<Command> cmdList;

	/**
	 * Constructor
	 * @param name name of the command
	 * @param modal true means the monitor dialog is modal and the command has to
	 *        complete or be canceled before any other action can occur
	 * @param canCancel true means the command can be canceled
	 */
	public CompoundBackgroundCommand(String name, boolean modal, boolean canCancel) {
		super(name, false, canCancel, modal);
		bkgroundCmdList = new ArrayList<BackgroundCommand>();
		cmdList = new ArrayList<Command>();
	}

	/* (non-Javadoc)
	 * @see ghidra.framework.cmd.BackgroundCommand#applyTo(ghidra.framework.model.DomainObject, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		for (int i = 0; i < bkgroundCmdList.size(); i++) {
			BackgroundCommand cmd = bkgroundCmdList.get(i);
			if (!cmd.applyTo(obj, monitor)) {
				setStatusMsg(cmd.getStatusMsg());
				return false;
			}
		}
		for (int i = 0; i < cmdList.size(); i++) {
			if (monitor.isCancelled()) {
				setStatusMsg("Cancelled");
				return false;
			}
			Command cmd = cmdList.get(i);

			if (!cmd.applyTo(obj)) {
				setStatusMsg(cmd.getStatusMsg());
				return false;
			}
		}
		return true;
	}

	/**
	 * Add a background command to this compound background command.
	 */
	public void add(BackgroundCommand cmd) {
		bkgroundCmdList.add(cmd);
	}

	/**
	 * Add a command to this compound background command.
	 */
	public void add(Command cmd) {
		cmdList.add(cmd);
	}

	/**
	 * Get the number of background commands in this compound background
	 * command.
	 */
	public int size() {
		return bkgroundCmdList.size();
	}

	/**
	 * @return true if no sub-commands have been added
	 */
	public boolean isEmpty() {
		return bkgroundCmdList.isEmpty();
	}
}
