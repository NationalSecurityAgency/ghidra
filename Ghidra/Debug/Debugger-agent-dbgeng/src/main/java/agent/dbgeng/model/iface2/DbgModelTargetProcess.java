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
package agent.dbgeng.model.iface2;

import java.util.concurrent.CompletableFuture;

import agent.dbgeng.dbgeng.DebugProcessId;
import agent.dbgeng.dbgeng.DebugSystemObjects;
import agent.dbgeng.manager.DbgEventsListenerAdapter;
import agent.dbgeng.manager.DbgProcess;
import agent.dbgeng.manager.cmd.DbgProcessSelectCommand;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.iface1.*;
import ghidra.dbg.target.TargetAggregate;
import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.util.PathUtils;

public interface DbgModelTargetProcess extends //
		TargetAggregate, //
		TargetProcess<DbgModelTargetProcess>, //
		DbgModelTargetExecutionStateful<DbgModelTargetProcess>, //
		DbgModelTargetAccessConditioned<DbgModelTargetProcess>, //
		DbgModelTargetAttacher<DbgModelTargetProcess>, //
		DbgModelTargetAttachable<DbgModelTargetProcess>, //
		DbgModelTargetLauncher<DbgModelTargetProcess>, //
		DbgModelTargetDeletable<DbgModelTargetProcess>, //
		DbgModelTargetDetachable<DbgModelTargetProcess>, //
		DbgModelTargetKillable<DbgModelTargetProcess>, //
		DbgModelTargetResumable<DbgModelTargetProcess>, //
		DbgModelTargetSteppable<DbgModelTargetProcess>, //
		DbgModelTargetInterruptible<DbgModelTargetProcess>, // 
		DbgEventsListenerAdapter, //
		DbgModelSelectableObject {

	public void processStarted(Long pid);

	public void processExited(Long exitCode);

	public DbgModelTargetThreadContainer getThreads();

	public DbgModelTargetModuleContainer getModules();

	public default DbgProcess getProcess() {
		DbgManagerImpl manager = getManager();
		DebugSystemObjects so = manager.getSystemObjects();
		try {
			String index = PathUtils.parseIndex(getName());
			Integer pid = Integer.decode(index);
			DebugProcessId id = so.getProcessIdBySystemId(pid);
			if (id == null) {
				id = so.getCurrentProcessId();
			}
			return manager.getProcessComputeIfAbsent(id, pid);
		}
		catch (IllegalArgumentException e) {
			return manager.getCurrentProcess();
		}
	}

	@Override
	public default CompletableFuture<Void> select() {
		DbgManagerImpl manager = getManager();
		DbgProcess process = getProcess();
		if (process == null) {
			process = manager.getEventProcess();
		}
		return manager.execute(new DbgProcessSelectCommand(manager, process));
	}
}
