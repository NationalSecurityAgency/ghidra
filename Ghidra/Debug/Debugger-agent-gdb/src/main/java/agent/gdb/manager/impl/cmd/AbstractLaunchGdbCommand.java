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

public abstract class AbstractLaunchGdbCommand extends AbstractGdbCommand<GdbThread> {

	protected AbstractLaunchGdbCommand(GdbManagerImpl manager) {
		super(manager);
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		evt = checkErrorViaCli(evt);
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
		else if (evt instanceof GdbThreadCreatedEvent) {
			pending.claim(evt);
		}
		return false;
	}

	@Override
	public GdbThread complete(GdbPendingCommand<?> pending) {
		pending.checkCompletion(GdbCommandRunningEvent.class);

		// Just take the first thread. Others are considered clones.
		GdbThreadCreatedEvent created = pending.findFirstOf(GdbThreadCreatedEvent.class);
		int tid = created.getThreadId();
		return manager.getThread(tid);
	}
}
