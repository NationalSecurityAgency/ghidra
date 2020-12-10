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
package agent.dbgeng.manager.cmd;

import agent.dbgeng.dbgeng.DebugClient;
import agent.dbgeng.dbgeng.DebugClient.DebugStatus;
import agent.dbgeng.manager.DbgEvent;
import agent.dbgeng.manager.DbgProcess;
import agent.dbgeng.manager.evt.*;
import agent.dbgeng.manager.impl.DbgManagerImpl;

/**
 * Implementation of {@link DbgProcess#kill()}
 */
public class DbgContinueCommand extends AbstractDbgCommand<Void> {
	public DbgContinueCommand(DbgManagerImpl manager) {
		super(manager);
	}

	@Override
	public boolean handle(DbgEvent<?> evt, DbgPendingCommand<?> pending) {
		if (evt instanceof AbstractDbgCompletedCommandEvent && pending.getCommand().equals(this)) {
			return evt instanceof DbgCommandErrorEvent ||
				!pending.findAllOf(DbgRunningEvent.class).isEmpty();
		}
		else if (evt instanceof DbgRunningEvent) {
			// Event happens no matter which interpreter received the command
			pending.claim(evt);
			return !pending.findAllOf(AbstractDbgCompletedCommandEvent.class).isEmpty();
		}
		return false;
	}

	@Override
	public void invoke() {
		DebugClient dbgeng = manager.getClient();
		dbgeng.getControl().setExecutionStatus(DebugStatus.GO);
	}
}
