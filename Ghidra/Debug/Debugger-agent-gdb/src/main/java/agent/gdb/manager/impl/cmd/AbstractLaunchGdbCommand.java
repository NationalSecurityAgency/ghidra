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

import agent.gdb.manager.GdbThread;
import agent.gdb.manager.evt.*;
import agent.gdb.manager.impl.*;
import agent.gdb.manager.impl.GdbManagerImpl.Interpreter;

public abstract class AbstractLaunchGdbCommand extends AbstractGdbCommand<GdbThread>
		implements MixinResumeInCliGdbCommand<GdbThread> {

	protected AbstractLaunchGdbCommand(GdbManagerImpl manager) {
		super(manager);
	}

	@Override
	public Interpreter getInterpreter() {
		//return getInterpreter(manager);

		/**
		 * A lot of good event-handling logic is factored in the Mixin interface. However, errors
		 * from CLI commands are catastrophically mishandled or just missed entirely, so we will
		 * still use MI2 for these.
		 */
		return Interpreter.MI2;
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		evt = checkErrorViaCli(evt);
		if (evt instanceof GdbThreadCreatedEvent) {
			pending.claim(evt);
		}
		return handleExpectingRunning(evt, pending);
	}

	@Override
	public GdbThread complete(GdbPendingCommand<?> pending) {
		completeOnRunning(pending);

		// Just take the first thread. Others are considered clones.
		GdbThreadCreatedEvent created = pending.findFirstOf(GdbThreadCreatedEvent.class);
		int tid = created.getThreadId();
		return manager.getThread(tid);
	}
}
