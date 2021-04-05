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
package agent.gdb.manager.impl.cmd;

import org.apache.commons.text.StringEscapeUtils;

import agent.gdb.manager.GdbManager;
import agent.gdb.manager.evt.AbstractGdbCompletedCommandEvent;
import agent.gdb.manager.evt.GdbConsoleOutputEvent;
import agent.gdb.manager.impl.*;

/**
 * Implementation of {@link GdbManager#console(String)} and similar
 */
public class GdbConsoleExecCommand extends AbstractGdbCommandWithThreadAndFrameId<String> {
	public enum Output {
		CONSOLE, CAPTURE;
	}

	private String command;
	private Output to;

	public GdbConsoleExecCommand(GdbManagerImpl manager, Integer threadId, Integer frameId,
			String command, Output to) {
		super(manager, threadId, frameId);
		this.command = command;
		this.to = to;
	}

	@Override
	public String encode(String threadPart, String framePart) {
		return "-interpreter-exec" + threadPart + framePart + " console \"" +
			StringEscapeUtils.escapeJava(command) + "\"";
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		if (evt instanceof AbstractGdbCompletedCommandEvent) {
			pending.claim(evt);
			return true;
		}
		else if (evt instanceof GdbConsoleOutputEvent && to == Output.CAPTURE) {
			GdbConsoleOutputEvent out = (GdbConsoleOutputEvent) evt;
			if (out.getInterpreter() == getInterpreter()) {
				pending.steal(evt);
			}
		}
		return false;
	}

	@Override
	public String complete(GdbPendingCommand<?> pending) {
		pending.checkCompletion(AbstractGdbCompletedCommandEvent.class);

		if (to == Output.CONSOLE) {
			return null;
		}
		StringBuilder builder = new StringBuilder();
		for (GdbConsoleOutputEvent out : pending.findAllOf(GdbConsoleOutputEvent.class)) {
			builder.append(out.getOutput());
		}
		return builder.toString();
	}

	public Output getOutputTo() {
		return to;
	}
}
