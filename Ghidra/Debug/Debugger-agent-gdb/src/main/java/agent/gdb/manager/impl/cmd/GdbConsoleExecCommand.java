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
import agent.gdb.manager.evt.*;
import agent.gdb.manager.impl.*;
import agent.gdb.manager.impl.GdbManagerImpl.Interpreter;

/**
 * Implementation of {@link GdbManager#console(String)} and similar
 */
public class GdbConsoleExecCommand extends AbstractGdbCommandWithThreadAndFrameId<String> {
	public enum CompletesWithRunning {
		/**
		 * Ignore {@code ^running} events, because they cannot complete this command
		 */
		CANNOT(AbstractGdbCompletedCommandEvent.class) {
			@Override
			boolean handleRunning(GdbCommandRunningEvent evt, GdbPendingCommand<?> pending) {
				return false;
			}
		},
		/**
		 * Allow any completion, including a {@code ^running} event, to complete this command
		 * 
		 * <p>
		 * Use this when the nature of the command is unknown, e.g., when it was input by the user.
		 */
		CAN(AbstractGdbCompletedCommandEvent.class) {
			@Override
			boolean handleRunning(GdbCommandRunningEvent evt, GdbPendingCommand<?> pending) {
				pending.claim(evt);
				return true;
			}
		},
		/**
		 * Require completion by a {@code ^running} event
		 */
		MUST(GdbCommandRunningEvent.class) {
			@Override
			boolean handleRunning(GdbCommandRunningEvent evt, GdbPendingCommand<?> pending) {
				pending.claim(evt);
				return true;
			}
		};

		private final Class<? extends AbstractGdbCompletedCommandEvent> completionClass;

		private CompletesWithRunning(
				Class<? extends AbstractGdbCompletedCommandEvent> completionClass) {
			this.completionClass = completionClass;
		}

		abstract boolean handleRunning(GdbCommandRunningEvent evt, GdbPendingCommand<?> pending);
	}

	public enum Output {
		CONSOLE, CAPTURE;
	}

	private final String command;
	private final Output to;
	private final CompletesWithRunning cwr;

	public GdbConsoleExecCommand(GdbManagerImpl manager, Integer threadId, Integer frameId,
			String command, Output to, CompletesWithRunning cwr) {
		super(manager, threadId, frameId);
		this.command = command;
		this.to = to;
		this.cwr = cwr;
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
		if (evt instanceof GdbCommandRunningEvent) {
			return cwr.handleRunning((GdbCommandRunningEvent) evt, pending);
		}
		else if (evt instanceof AbstractGdbCompletedCommandEvent) {
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
		pending.checkCompletion(cwr.completionClass);

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
