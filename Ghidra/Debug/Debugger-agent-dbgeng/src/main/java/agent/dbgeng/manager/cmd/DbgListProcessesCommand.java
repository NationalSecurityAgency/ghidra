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

import agent.dbgeng.dbgeng.DebugProcessId;
import agent.dbgeng.dbgeng.DebugSystemObjects;
import agent.dbgeng.manager.DbgCause.Causes;
import agent.dbgeng.manager.DbgManager;
import agent.dbgeng.manager.DbgProcess;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import ghidra.util.Msg;

/**
 * Implementation of {@link DbgManager#listProcesses()}
 */
public class DbgListProcessesCommand extends AbstractDbgCommand<Map<DebugProcessId, DbgProcess>> {
	private List<DebugProcessId> updatedProcessIds;

	public DbgListProcessesCommand(DbgManagerImpl manager) {
		super(manager);
	}

	@Override
	public Map<DebugProcessId, DbgProcess> complete(DbgPendingCommand<?> pending) {
		Map<DebugProcessId, DbgProcess> allProcesses = manager.getKnownProcesses();
		Set<DebugProcessId> cur = allProcesses.keySet();
		for (DebugProcessId id : updatedProcessIds) {
			if (cur.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			// Need to create the inferior as if we received =thread-group-created
			Msg.warn(this, "Resync: Was missing group: i" + id);
			DebugSystemObjects so = manager.getSystemObjects();
			so.setCurrentProcessId(id);
			int pid = so.getCurrentProcessSystemId();
			manager.getProcessComputeIfAbsent(id, pid);
		}
		for (DebugProcessId id : new ArrayList<>(cur)) {
			if (updatedProcessIds.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			// Need to remove the inferior as if we received =thread-group-removed
			Msg.warn(this, "Resync: Had extra group: i" + id);
			manager.removeProcess(id, Causes.UNCLAIMED);
		}
		return allProcesses;
	}

	@Override
	public void invoke() {
		DebugSystemObjects so = manager.getSystemObjects();
		updatedProcessIds = so.getProcesses();
	}
}
