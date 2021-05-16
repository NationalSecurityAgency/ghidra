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

import agent.gdb.manager.GdbManager.StepCmd;
import agent.gdb.manager.GdbThread;
import agent.gdb.manager.impl.*;
import agent.gdb.manager.impl.GdbManagerImpl.Interpreter;

/**
 * Implementation of {@link GdbThread#stepInstruction()}
 */
public class GdbStepCommand extends AbstractGdbCommandWithThreadId<Void>
		implements MixinResumeInCliGdbCommand {
	protected final StepCmd cmd;

	public GdbStepCommand(GdbManagerImpl manager, Integer threadId, StepCmd cmd) {
		super(manager, threadId);
		this.cmd = cmd;
	}

	@Override
	public Interpreter getInterpreter() {
		return getInterpreter(manager);
	}

	@Override
	protected String encode(String threadPart) {
		if (getInterpreter() == Interpreter.CLI) {
			return cmd.cli;
		}
		return cmd.mi2 + threadPart;
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		evt = checkErrorViaCli(evt); // TODO: Deprecated, since that hack can crash GDB
		return handleExpectingRunning(evt, pending);
	}

	@Override
	public Void complete(GdbPendingCommand<?> pending) {
		return completeOnRunning(pending);
	}
}
