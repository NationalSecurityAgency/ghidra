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

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.manager.*;
import agent.dbgeng.manager.evt.*;
import agent.dbgeng.manager.impl.DbgManagerImpl;

/**
 * Implementation of {@link DbgProcess#fileExecAndSymbols(String)}
 */
public class DbgRunCommand extends AbstractDbgCommand<DbgThread> {

	public DbgRunCommand(DbgManagerImpl manager) {
		super(manager);
	}

	@Override
	public boolean handle(DbgEvent<?> evt, DbgPendingCommand<?> pending) {
		if (evt instanceof AbstractDbgCompletedCommandEvent && pending.getCommand().equals(this)) {
			pending.claim(evt);
			return true;
		}
		else if (evt instanceof DbgRunningEvent) {
			pending.claim(evt);
		}
		else if (evt instanceof DbgThreadCreatedEvent) {
			pending.claim(evt);
		}
		return false;
	}

	@Override
	public DbgThread complete(DbgPendingCommand<?> pending) {
		// Just take the first thread. Others are considered clones.
		DbgThreadCreatedEvent created = pending.findFirstOf(DbgThreadCreatedEvent.class);
		DebugThreadInfo info = created.getInfo();
		DebugSystemObjects so = manager.getSystemObjects();
		DebugThreadId tid = so.getThreadIdByHandle(info.handle);
		return manager.getThread(tid);
	}

	@Override
	public void invoke() {
		// TODO Auto-generated method stub
	}
}
