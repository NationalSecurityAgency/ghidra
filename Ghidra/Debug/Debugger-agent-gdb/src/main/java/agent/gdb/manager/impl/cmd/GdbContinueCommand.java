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

import agent.gdb.manager.GdbInferior;
import agent.gdb.manager.evt.*;
import agent.gdb.manager.impl.*;
import agent.gdb.manager.impl.GdbManagerImpl.Interpreter;
import ghidra.util.Msg;

/**
 * Implementation of {@link GdbInferior#cont()}
 */
public class GdbContinueCommand extends AbstractGdbCommandWithThreadId<Void> {
	public GdbContinueCommand(GdbManagerImpl manager, Integer threadId) {
		super(manager, threadId);
	}

	@Override
	public String encode(String threadPart) {
		switch (getInterpreter()) {
			case CLI:
				return "continue";
			case MI2:
				return "-exec-continue" + threadPart;
			default:
				throw new AssertionError();
		}
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		if (evt instanceof AbstractGdbCompletedCommandEvent) {
			if (!pending.hasAny(AbstractGdbCompletedCommandEvent.class)) {
				pending.claim(evt);
			}
			return evt instanceof GdbCommandErrorEvent || pending.hasAny(GdbRunningEvent.class);
		}
		else if (evt instanceof GdbRunningEvent) {
			// Event happens no matter which interpreter received the command
			pending.claim(evt);
			return pending.hasAny(AbstractGdbCompletedCommandEvent.class);
		}
		else if (evt instanceof GdbConsoleOutputEvent) {
			Msg.debug(this, "EXAMINING: " + evt);
			if (pending.hasAny(GdbCommandRunningEvent.class)) {
				// Only attempt to process/claim the first line after our command
				return false;
			}
			GdbConsoleOutputEvent out = (GdbConsoleOutputEvent) evt;
			if (out.getOutput().trim().equals("continue")) {
				// Echoed back my command
				return false;
			}
			pending.claim(evt);
			if (out.getOutput().trim().startsWith("Continuing") &&
				!pending.hasAny(GdbCommandRunningEvent.class)) {
				pending.claim(new GdbCommandRunningEvent());
				return pending.hasAny(GdbRunningEvent.class);
			}
			else {
				pending.claim(GdbCommandErrorEvent.fromMessage(out.getOutput()));
				return true;
			}
		}
		return false;
	}

	@Override
	public Interpreter getInterpreter() {
		if (manager.hasCli()) {
			return Interpreter.CLI;
		}
		return Interpreter.MI2;
	}

	@Override
	public Void complete(GdbPendingCommand<?> pending) {
		pending.checkCompletion(GdbCommandRunningEvent.class);
		return null;
	}
}
