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
package agent.lldb.manager.cmd;

import SWIG.StateType;
import agent.lldb.manager.LldbCommand;
import agent.lldb.manager.LldbEvent;
import agent.lldb.manager.evt.LldbCommandDoneEvent;
import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * A base class for interacting with specific Lldb commands
 *
 * @param <T> the type of object "returned" by the command
 */
public abstract class AbstractLldbCommand<T> implements LldbCommand<T> {
	protected final LldbManagerImpl manager;

	/**
	 * Construct a new command to be executed by the given manager
	 * 
	 * @param manager the manager to execute the command
	 */
	protected AbstractLldbCommand(LldbManagerImpl manager) {
		this.manager = manager;
	}

	@Override
	public boolean validInState(StateType state) {
		return true; // With dual interpreters, shouldn't have to worry.
	}

	@Override
	public boolean handle(LldbEvent<?> evt, LldbPendingCommand<?> pending) {
		if (evt instanceof LldbCommandDoneEvent) {
			if (pending.getCommand().equals(((LldbCommandDoneEvent) evt).getCmd())) {
				return true;
			}
		}
		return false;
	}

	@Override
	public T complete(LldbPendingCommand<?> pending) {
		return null;
	}

	@Override
	public void invoke() {
		// Nothing
	}
}
