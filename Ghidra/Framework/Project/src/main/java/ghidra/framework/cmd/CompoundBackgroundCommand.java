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

import java.util.ArrayList;

import ghidra.framework.model.DomainObject;
import ghidra.util.task.TaskMonitor;

/**
 * Compound command to handle multiple background commands.
 * 
 * @param <T> {@link DomainObject} implementation interface
 */
public class CompoundBackgroundCommand<T extends DomainObject> extends BackgroundCommand<T> {

	private ArrayList<Command<T>> cmdList;

	/**
	 * Constructor
	 * @param name name of the command
	 * @param modal true means the monitor dialog is modal and the command has to
	 *        complete or be canceled before any other action can occur
	 * @param canCancel true means the command can be canceled
	 */
	public CompoundBackgroundCommand(String name, boolean modal, boolean canCancel) {
		super(name, false, canCancel, modal);
		cmdList = new ArrayList<>();
	}

	@Override
	public boolean applyTo(T obj, TaskMonitor monitor) {
		// Run commands in the order they were added
		for (Command<T> cmd : cmdList) {
			if (monitor.isCancelled()) {
				setStatusMsg("Cancelled");
				return false;
			}
			boolean success;
			if (cmd instanceof BackgroundCommand<T> bcmd) {
				success = bcmd.applyTo(obj, monitor);
			}
			else {
				success = cmd.applyTo(obj);
			}
			if (!success) {
				setStatusMsg(cmd.getStatusMsg());
				return false;
			}
		}
		return true;
	}

	/**
	 * Add a command to this compound background command.
	 * @param cmd command to be added
	 */
	public void add(Command<T> cmd) {
		cmdList.add(cmd);
	}

	/**
	 * Get the number of background commands in this compound background
	 * command.
	 * @return the number of commands
	 */
	public int size() {
		return cmdList.size();
	}

	/**
	 * @return true if no sub-commands have been added
	 */
	public boolean isEmpty() {
		return cmdList.isEmpty();
	}
}
