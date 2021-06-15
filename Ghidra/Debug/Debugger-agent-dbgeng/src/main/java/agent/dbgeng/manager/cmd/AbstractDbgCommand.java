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
package agent.dbgeng.manager.cmd;

import agent.dbgeng.manager.*;
import agent.dbgeng.manager.evt.DbgCommandDoneEvent;
import agent.dbgeng.manager.impl.DbgManagerImpl;

/**
 * A base class for interacting with specific Dbg commands
 *
 * @param <T> the type of object "returned" by the command
 */
public abstract class AbstractDbgCommand<T> implements DbgCommand<T> {
	protected final DbgManagerImpl manager;

	/**
	 * Construct a new command to be executed by the given manager
	 * 
	 * @param manager the manager to execute the command
	 */
	protected AbstractDbgCommand(DbgManagerImpl manager) {
		this.manager = manager;
	}

	@Override
	public boolean validInState(DbgState state) {
		return true; // With dual interpreters, shouldn't have to worry.
	}

	@Override
	public boolean handle(DbgEvent<?> evt, DbgPendingCommand<?> pending) {
		if (evt instanceof DbgCommandDoneEvent) {
			if (pending.getCommand().equals(((DbgCommandDoneEvent) evt).getCmd())) {
				return true;
			}
		}
		return false;
	}

	@Override
	public T complete(DbgPendingCommand<?> pending) {
		return null;
	}

	@Override
	public void invoke() {
		// Nothing
	}
}
