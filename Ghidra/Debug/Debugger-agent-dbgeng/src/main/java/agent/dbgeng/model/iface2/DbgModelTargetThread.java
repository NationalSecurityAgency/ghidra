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

import agent.dbgeng.dbgeng.DebugSystemObjects;
import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.manager.*;
import agent.dbgeng.manager.cmd.DbgSetActiveThreadCommand;
import agent.dbgeng.manager.impl.*;
import agent.dbgeng.model.iface1.*;
import agent.dbgeng.model.impl.DbgModelTargetStackImpl;
import ghidra.dbg.target.TargetThread;
import ghidra.dbg.util.PathUtils;

public interface DbgModelTargetThread extends //
		TargetThread, //
		DbgModelTargetAccessConditioned, //
		DbgModelTargetExecutionStateful, //
		DbgModelTargetSteppable, //
		DbgEventsListenerAdapter, //
		DbgModelSelectableObject {

	public default DbgThread getThread() {
		DbgManagerImpl manager = getManager();
		DebugSystemObjects so = manager.getSystemObjects();
		try {
			String index = PathUtils.parseIndex(getName());
			int tid = Integer.decode(index);
			DebugThreadId id = so.getThreadIdBySystemId(tid);
			if (id == null) {
				id = so.getCurrentThreadId();
			}
			DbgModelTargetProcess parentProcess = getParentProcess();
			DbgProcessImpl process = (DbgProcessImpl) parentProcess.getProcess();
			DbgThreadImpl thread = manager.getThreadComputeIfAbsent(id, process, tid);
			return thread;
		}
		catch (IllegalArgumentException e) {
			return manager.getCurrentThread();
		}
	}

	@Override
	public default CompletableFuture<Void> setActive() {
		DbgManagerImpl manager = getManager();
		DbgThread thread = getThread();
		return manager.execute(new DbgSetActiveThreadCommand(manager, thread, null));
	}

	public DbgModelTargetStackImpl getStack();

	public String getExecutingProcessorType();

	public void threadStateChangedSpecific(DbgState state, DbgReason reason);

}
