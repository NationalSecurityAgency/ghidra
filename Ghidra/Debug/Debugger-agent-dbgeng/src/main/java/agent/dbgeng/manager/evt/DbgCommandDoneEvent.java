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
package agent.dbgeng.manager.evt;

import agent.dbgeng.manager.DbgCommand;
import agent.dbgeng.manager.DbgState;

/**
 * The event corresponding with "{@code ^done}"
 */
public class DbgCommandDoneEvent extends AbstractDbgCompletedCommandEvent {

	private DbgCommand<?> cmd;

	/**
	 * Construct a new event, parsing the tail for information
	 */
	public DbgCommandDoneEvent() {
		super();
	}

	public DbgCommandDoneEvent(DbgCommand<?> cmd) {
		super(cmd.toString());
		this.cmd = cmd;
	}

	@Override
	public DbgState newState() {
		return DbgState.STOPPED;
	}

	public DbgCommand<?> getCmd() {
		return cmd;
	}

}
