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
import agent.gdb.manager.GdbManager.Channel;
import agent.gdb.manager.evt.AbstractGdbCompletedCommandEvent;
import agent.gdb.manager.evt.GdbConsoleOutputEvent;
import agent.gdb.manager.impl.*;
import agent.gdb.manager.impl.GdbManagerImpl.Interpreter;

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

	/**
	 * TODO: I think there should be a separate command for arbitrary CLI input. I'm not sure yet
	 * whether it should wait in the queue or just be sent immediately.
	 */
	@Override
	public Interpreter getInterpreter() {
		/*if (to == Output.CONSOLE && manager.hasCli() && threadId == null && frameId == null) {
			return Interpreter.CLI;
		}*/
		return Interpreter.MI2;
	}

	@Override
	public String encode(String threadPart, String framePart) {
		switch (getInterpreter()) {
			case CLI:
				return command;
			case MI2:
				return "-interpreter-exec" + threadPart + framePart + " console \"" +
					StringEscapeUtils.escapeJava(command) + "\"";
			default:
				throw new AssertionError();
		}
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		if (getInterpreter() == Interpreter.CLI) {
			// At the very least, I should expect to see the (gdb) prompt.
			if (evt instanceof GdbConsoleOutputEvent) {
				GdbConsoleOutputEvent out = (GdbConsoleOutputEvent) evt;
				if (out.getInterpreter() == Interpreter.CLI) {
					return true;
				}
			}
			return false;
		}
		// MI2
		if (evt instanceof AbstractGdbCompletedCommandEvent) {
			pending.claim(evt);
			return true;
		}
		else if (evt instanceof GdbConsoleOutputEvent) {
			GdbConsoleOutputEvent out = (GdbConsoleOutputEvent) evt;
			// This is not a great check...
			if (out.getInterpreter() == Interpreter.MI2 && ">".equals(out.getOutput().trim()) &&
				!command.trim().startsWith("ec")) {
				manager.injectInput(Interpreter.MI2, "end\n");
				manager.synthesizeConsoleOut(Channel.STDERR,
					"Ghidra GDB Agent: Multi-line / follow-up input is not currently supported. " +
						"I just typed 'end' for you.\n");
			}
			if (to == Output.CAPTURE) {
				if (out.getInterpreter() == getInterpreter()) {
					pending.steal(evt);
				}
			}
		}
		return false;
	}

	@Override
	public String complete(GdbPendingCommand<?> pending) {
		if (getInterpreter() == Interpreter.CLI) {
			return null;
		}
		// MI2
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

	@Override
	public boolean isFocusInternallyDriven() {
		return to == Output.CAPTURE;
	}
}
