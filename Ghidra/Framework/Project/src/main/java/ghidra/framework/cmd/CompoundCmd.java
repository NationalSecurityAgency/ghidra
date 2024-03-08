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

import java.util.ArrayList;

/**
 * Implementation for multiple commands that are done as a unit.
 * 
 * Multiple commands may be added to this one so that multiple changes can be
 * applied to the domain object as unit.
 * 
 * @param <T> {@link DomainObject} implementation interface
 */
public class CompoundCmd<T extends DomainObject> implements Command<T> {
	private ArrayList<Command<T>> cmds;
	private String statusMsg;
	private String name;

	/**
	 * Constructor for CompoundCmd.
	 * 
	 * @param name the name of the command
	 */
	public CompoundCmd(String name) {
		cmds = new ArrayList<>();
		this.name = name;
	}

	@Override
	public boolean applyTo(T obj) {
		for (Command<T> cmd : cmds) {
			if (!cmd.applyTo(obj)) {
				statusMsg = cmd.getStatusMsg();
				return false;
			}
		}
		return true;
	}

	@Override
	public String getStatusMsg() {
		return statusMsg;
	}

	@Override
	public String getName() {
		return name;
	}

	/**
	 * Add the given command to this command.
	 * 
	 * @param cmd command to add to this command
	 */
	public void add(Command<T> cmd) {
		cmds.add(cmd);
	}

	/**
	 * Return the number of commands that are part of this compound command.
	 * 
	 * @return the number of commands that have been added to this one.
	 */
	public int size() {
		return cmds.size();
	}

}
