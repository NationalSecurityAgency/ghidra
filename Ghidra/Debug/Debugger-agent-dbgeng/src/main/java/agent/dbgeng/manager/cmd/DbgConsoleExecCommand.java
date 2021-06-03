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

import agent.dbgeng.dbgeng.DebugControl;
import agent.dbgeng.manager.DbgEvent;
import agent.dbgeng.manager.DbgManager;
import agent.dbgeng.manager.evt.*;
import agent.dbgeng.manager.impl.DbgManagerImpl;

/**
 * Implementation of {@link DbgManager#console(String)} and similar
 */
public class DbgConsoleExecCommand extends AbstractDbgCommand<String> {
	public enum Output {
		CONSOLE, CAPTURE;
	}

	private String command;
	private Output to;

	public DbgConsoleExecCommand(DbgManagerImpl manager, String command, Output to) {
		super(manager);
		this.command = command;
		this.to = to;
	}

	@Override
	public boolean handle(DbgEvent<?> evt, DbgPendingCommand<?> pending) {
		if (evt instanceof AbstractDbgCompletedCommandEvent && pending.getCommand().equals(this)) {
			return true;
		}
		else if (evt instanceof DbgConsoleOutputEvent && to == Output.CAPTURE) {
			pending.steal(evt);
		}
		return false;
	}

	@Override
	public String complete(DbgPendingCommand<?> pending) {
		if (to == Output.CONSOLE) {
			return null;
		}
		StringBuilder builder = new StringBuilder();
		for (DbgConsoleOutputEvent out : pending.findAllOf(DbgConsoleOutputEvent.class)) {
			builder.append(out.getOutput());
		}
		return builder.toString();
	}

	@Override
	public void invoke() {
		DebugControl control = manager.getControl();
		control.execute(command);
		manager.processEvent(new DbgPromptChangedEvent(control.getPromptText()));
	}
}
