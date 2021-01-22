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

/**
 * Implementation of {@link GdbInferior#cont()}
 */
public class GdbContinueCommand extends AbstractGdbCommandWithThreadId<Void> {
	public GdbContinueCommand(GdbManagerImpl manager, Integer threadId) {
		super(manager, threadId);
	}

	@Override
	public Interpreter getInterpreter() {
		if (manager.hasCli()) {
			return Interpreter.CLI;
		}
		return Interpreter.MI2;
	}

	@Override
	public String encode(String threadPart) {
		switch (getInterpreter()) {
			case CLI:
				// The significance is the Pty, not so much the actual command
				// Using MI2 simplifies event processing (no console output parsing)
				return "interpreter-exec mi2 \"-exec-continue" + threadPart + "\"";
			case MI2:
				return "-exec-continue" + threadPart;
			default:
				throw new AssertionError();
		}
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		if (evt instanceof GdbCommandRunningEvent) {
			pending.claim(evt);
			return pending.hasAny(GdbRunningEvent.class);
		}
		else if (evt instanceof AbstractGdbCompletedCommandEvent) {
			pending.claim(evt);
			return true; // Not the expected Completed event 
		}
		else if (evt instanceof GdbRunningEvent) {
			// Event happens no matter which interpreter received the command
			pending.claim(evt);
			return pending.hasAny(GdbCommandRunningEvent.class);
		}
		return false;
	}

	@Override
	public Void complete(GdbPendingCommand<?> pending) {
		pending.checkCompletion(GdbCommandRunningEvent.class);
		return null;
	}
}
