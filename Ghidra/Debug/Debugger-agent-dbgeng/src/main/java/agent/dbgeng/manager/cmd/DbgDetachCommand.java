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

import java.util.ArrayList;
import java.util.Collection;

import agent.dbgeng.dbgeng.DebugClient;
import agent.dbgeng.manager.DbgCause;
import agent.dbgeng.manager.DbgProcess;
import agent.dbgeng.manager.impl.*;

/**
 * Implementation of {@link DbgProcess#kill()}
 */
public class DbgDetachCommand extends AbstractDbgCommand<Void> {
	private final DbgProcessImpl process;

	public DbgDetachCommand(DbgManagerImpl manager, DbgProcessImpl process) {
		super(manager);
		this.process = process;
	}

	@Override
	public Void complete(DbgPendingCommand<?> pending) {
		// TODO: necessary?
		Collection<DbgThreadImpl> threads = new ArrayList<>(process.getKnownThreadsImpl().values());
		for (DbgThreadImpl t : threads) {
			manager.fireThreadExited(t.getId(), process, pending);
			t.remove();
		}
		manager.getEventListeners().fire.processRemoved(process.getId(), DbgCause.Causes.UNCLAIMED);
		return null;
	}

	@Override
	public void invoke() {
		DebugClient dbgeng = manager.getClient();
		dbgeng.detachCurrentProcess();
	}
}
