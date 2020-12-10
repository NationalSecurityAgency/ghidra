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

import agent.gdb.manager.GdbManager.ExecSuffix;
import agent.gdb.manager.GdbThread;
import agent.gdb.manager.evt.*;
import agent.gdb.manager.impl.*;

/**
 * Implementation of {@link GdbThread#stepInstruction()}
 */
public class GdbStepCommand extends AbstractGdbCommandWithThreadId<Void> {
	protected final ExecSuffix suffix;

	public GdbStepCommand(GdbManagerImpl manager, Integer threadId, ExecSuffix suffix) {
		super(manager, threadId);
		this.suffix = suffix;
	}

	@Override
	protected String encode(String threadPart) {
		return "-exec-" + suffix + threadPart;
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
