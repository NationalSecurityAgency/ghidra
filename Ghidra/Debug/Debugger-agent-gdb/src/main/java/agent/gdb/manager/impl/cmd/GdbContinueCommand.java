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
import agent.gdb.manager.impl.*;
import agent.gdb.manager.impl.GdbManagerImpl.Interpreter;

/**
 * Implementation of {@link GdbInferior#cont()}
 */
public class GdbContinueCommand extends AbstractGdbCommandWithThreadId<Void>
		implements MixinResumeInCliGdbCommand {
	public GdbContinueCommand(GdbManagerImpl manager, Integer threadId) {
		super(manager, threadId);
	}

	@Override
	public Interpreter getInterpreter() {
		return getInterpreter(manager);
	}

	@Override
	public String encode(String threadPart) {
		if (getInterpreter() == Interpreter.CLI) {
			return "continue";
		}
		return "-exec-continue" + threadPart;
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
