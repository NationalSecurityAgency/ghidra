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

import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.dbgeng.DebugThreadRecord;
import agent.dbgeng.manager.DbgEventsListenerAdapter;
import agent.dbgeng.manager.DbgReason;
import agent.dbgeng.manager.DbgState;
import agent.dbgeng.manager.DbgThread;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.manager.impl.DbgProcessImpl;
import agent.dbgeng.manager.impl.DbgThreadImpl;
import agent.dbgeng.model.iface1.DbgModelSelectableObject;
import agent.dbgeng.model.iface1.DbgModelTargetAccessConditioned;
import agent.dbgeng.model.iface1.DbgModelTargetExecutionStateful;
import agent.dbgeng.model.iface1.DbgModelTargetSteppable;
import agent.dbgeng.model.impl.DbgModelTargetStackImpl;
import ghidra.dbg.target.TargetAggregate;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetThread;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;

public interface DbgModelTargetThread extends //
		TargetThread, //
		TargetAggregate, //
		DbgModelTargetAccessConditioned, //
		DbgModelTargetExecutionStateful, //
		DbgModelTargetSteppable, //
		DbgEventsListenerAdapter, //
		DbgModelSelectableObject {

	public default DbgThread getThread() {
		return getThread(false);
	}

	public default DbgThread getThread(boolean fire) {
		DbgManagerImpl manager = getManager();
		try {
			DbgModelTargetProcess parentProcess = getParentProcess();
			DbgProcessImpl process = parentProcess == null ? null : (DbgProcessImpl) parentProcess.getProcess();
			String index = PathUtils.parseIndex(getName());
			Long tid = Long.decode(index);
			DebugThreadId id = new DebugThreadRecord(tid);
			DbgThreadImpl thread = manager.getThreadComputeIfAbsent(id, process, tid, fire);
			return thread;
		}
		catch (IllegalArgumentException e) {
			return manager.getCurrentThread();
		}
	}

	@TargetMethod.Export("Step to Address (pa)")
	public default CompletableFuture<Void> stepToAddress(
			@TargetMethod.Param(
				description = "The target address",
				display = "StopAddress",
				name = "address") Address address) {
		return getModel().gateFuture(getThread().stepToAddress(address.toString(false)));
	}

	@TargetMethod.Export("Trace to Address (ta)")
	public default CompletableFuture<Void> traceToAddress(
			@TargetMethod.Param(
				description = "The target address",
				display = "StopAddress",
				name = "address") Address address) {
		return getModel().gateFuture(getThread().traceToAddress(address.toString(false)));
	}

	@Override
	public default CompletableFuture<Void> setActive() {
		DbgManagerImpl manager = getManager();
		DbgProcessImpl process = (DbgProcessImpl) getParentProcess().getProcess();
		manager.setActiveProcess(process);
		return manager.setActiveThread(getThread());
	}

	public DbgModelTargetStackImpl getStack();

	public String getExecutingProcessorType();

	public void threadStateChangedSpecific(DbgState state, DbgReason reason);

}
