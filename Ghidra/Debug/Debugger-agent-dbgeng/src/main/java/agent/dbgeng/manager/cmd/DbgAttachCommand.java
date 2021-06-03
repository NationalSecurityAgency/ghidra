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

import java.util.LinkedHashSet;
import java.util.Set;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DebugClient.DebugAttachFlags;
import agent.dbgeng.manager.*;
import agent.dbgeng.manager.evt.*;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.manager.impl.DbgProcessImpl;
import ghidra.comm.util.BitmaskSet;

/**
 * Implementation of {@link DbgProcess#kill()}
 */
public class DbgAttachCommand extends AbstractDbgCommand<Set<DbgThread>> {

	private DbgProcessCreatedEvent created = null;
	private boolean completed = false;
	private DbgProcessImpl proc;
	private BitmaskSet<DebugAttachFlags> flags;

	public DbgAttachCommand(DbgManagerImpl manager, DbgProcessImpl proc,
			BitmaskSet<DebugAttachFlags> flags) {
		super(manager);
		this.proc = proc;
		this.flags = flags;
	}

	@Override
	public boolean handle(DbgEvent<?> evt, DbgPendingCommand<?> pending) {
		if (evt instanceof AbstractDbgCompletedCommandEvent && pending.getCommand().equals(this)) {
			completed = true;
		}
		else if (evt instanceof DbgProcessCreatedEvent) {
			created = (DbgProcessCreatedEvent) evt;
		}
		else if (evt instanceof DbgThreadCreatedEvent) {
			pending.claim(evt);
		}
		else if (evt instanceof DbgStoppedEvent) {
			pending.claim(evt);
		}
		return completed && (created != null);
	}

	@Override
	public Set<DbgThread> complete(DbgPendingCommand<?> pending) {
		DebugSystemObjects so = manager.getSystemObjects();
		Set<DbgThread> threads = new LinkedHashSet<>();
		for (DbgThreadCreatedEvent adds : pending.findAllOf(DbgThreadCreatedEvent.class)) {
			DebugThreadInfo info = adds.getInfo();
			DebugThreadId tid = so.getThreadIdByHandle(info.handle);
			threads.add(manager.getThread(tid));
		}
		return threads;
	}

	@Override
	public void invoke() {
		DebugClient dbgeng = manager.getClient();
		dbgeng.attachProcess(dbgeng.getLocalServer(), proc.getPid().intValue(), flags);

		manager.waitForEventEx();
	}
}
