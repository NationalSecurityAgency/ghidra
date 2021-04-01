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

import java.util.*;

import agent.dbgeng.dbgeng.DebugSystemObjects;
import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.manager.DbgThread;
import agent.dbgeng.manager.impl.*;
import ghidra.util.Msg;

public class DbgListMappingsCommand extends AbstractDbgCommand<Map<Long, DbgSectionImpl>> {
	protected final DbgProcessImpl process;
	private List<DebugThreadId> updatedThreadIds;

	public DbgListMappingsCommand(DbgManagerImpl manager, DbgProcessImpl process) {
		super(manager);
		this.process = process;
	}

	@Override
	public Map<Long, DbgSectionImpl> complete(DbgPendingCommand<?> pending) {
		Map<DebugThreadId, DbgThread> threads = process.getKnownThreads();
		Set<DebugThreadId> cur = threads.keySet();
		DebugSystemObjects so = manager.getSystemObjects();
		DebugThreadId previous = so.getCurrentThreadId();
		for (DebugThreadId id : updatedThreadIds) {
			if (cur.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			// Need to create the thread as if we receive =thread-created
			Msg.warn(this, "Resync: Was missing thread: " + id);
			so.setCurrentThreadId(id);
			int tid = so.getCurrentThreadSystemId();
			manager.getThreadComputeIfAbsent(id, process, tid);
		}
		for (DebugThreadId id : new ArrayList<>(cur)) {
			if (updatedThreadIds.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			// Need to remove the thread as if we received =thread-exited
			Msg.warn(this, "Resync: Had extra thread: " + id);
			process.removeThread(id);
			manager.removeThread(id);
		}
		so.setCurrentThreadId(previous);
		return process.getKnownMappings();
	}

	@Override
	public void invoke() {
		//TODO
	}

}
