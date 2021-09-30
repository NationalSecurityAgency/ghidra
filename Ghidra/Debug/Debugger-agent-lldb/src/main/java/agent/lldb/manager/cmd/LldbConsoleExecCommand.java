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

import agent.lldb.manager.LldbEvent;
import agent.lldb.manager.evt.AbstractLldbCompletedCommandEvent;
import agent.lldb.manager.evt.LldbConsoleOutputEvent;
import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * Implementation of {@link LldbManager#console(String)} and similar
 */
public class LldbConsoleExecCommand extends AbstractLldbCommand<String> {
	public enum Output {
		CONSOLE, CAPTURE;
	}

	private String command;
	private Output to;

	public LldbConsoleExecCommand(LldbManagerImpl manager, String command, Output to) {
		super(manager);
		this.command = command;
		this.to = to;
	}

	@Override
	public boolean handle(LldbEvent<?> evt, LldbPendingCommand<?> pending) {
		if (evt instanceof AbstractLldbCompletedCommandEvent && pending.getCommand().equals(this)) {
			return true;
		}
		else if (evt instanceof LldbConsoleOutputEvent && to == Output.CAPTURE) {
			pending.steal(evt);
		}
		return false;
	}

	@Override
	public String complete(LldbPendingCommand<?> pending) {
		if (to == Output.CONSOLE) {
			return null;
		}
		StringBuilder builder = new StringBuilder();
		for (LldbConsoleOutputEvent out : pending.findAllOf(LldbConsoleOutputEvent.class)) {
			builder.append(out.getOutput());
		}
		return builder.toString();
	}

	@Override
	public void invoke() {
		manager.getClient().execute(command);
	}
}
