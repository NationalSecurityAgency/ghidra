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
package agent.dbgeng.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.dbgeng.dbgeng.DebugProcessId;
import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.manager.*;
import agent.dbgeng.model.iface2.*;
import ghidra.dbg.target.TargetAccessConditioned.TargetAccessibility;
import ghidra.dbg.target.TargetObject;
import ghidra.util.datastruct.WeakValueHashMap;

public class DbgModelTargetProcessContainerImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetProcessContainer {

	protected final Map<DebugProcessId, DbgModelTargetProcess> processesById =
		new WeakValueHashMap<>();

	public DbgModelTargetProcessContainerImpl(DbgModelTargetSession session) {
		super(session.getModel(), session, "Processes", "ProcessContainer");

		getManager().addEventsListener(this);
	}

	@Override
	public void processAdded(DbgProcess proc, DbgCause cause) {
		DbgModelTargetSession session = (DbgModelTargetSession) getImplParent();
		session.setAccessibility(TargetAccessibility.ACCESSIBLE);
		DbgModelTargetProcess process = getTargetProcess(proc);
		changeElements(List.of(), List.of(process), Map.of(), "Added");
		process.processStarted(proc.getPid());
		getListeners().fire(TargetEventScopeListener.class)
				.event(this, null, TargetEventType.PROCESS_CREATED, "Process " + proc.getId() +
					" started " + "notepad.exe" + " pid=" + proc.getPid(), List.of(process));
	}

	@Override
	public void processStarted(DbgProcess proc, DbgCause cause) {
		DbgModelTargetProcess process = getTargetProcess(proc);
		process.processStarted(proc.getPid());
	}

	@Override
	public void processExited(DbgProcess proc, DbgCause cause) {
		DbgModelTargetProcess process = getTargetProcess(proc);
		process.processExited(proc.getExitCode());
		getListeners().fire(TargetEventScopeListener.class)
				.event(this, null, TargetEventType.PROCESS_EXITED,
					"Process " + proc.getId() + " exited code=" + proc.getExitCode(),
					List.of(process));
	}

	@Override
	public void processRemoved(DebugProcessId processId, DbgCause cause) {
		synchronized (this) {
			processesById.remove(processId);
		}
		changeElements(List.of( //
			DbgModelTargetProcessImpl.indexProcess(processId) //
		), List.of(), Map.of(), "Removed");
	}

	@Override
	public void threadCreated(DbgThread thread, DbgCause cause) {
		DbgModelTargetProcess process = getTargetProcess(thread.getProcess());
		process.getThreads().threadCreated(thread);
	}

	@Override
	public void threadStateChanged(DbgThread thread, DbgState state, DbgCause cause,
			DbgReason reason) {
		DbgModelTargetProcess process = getTargetProcess(thread.getProcess());
		process.threadStateChanged(thread, state, cause, reason);
	}

	@Override
	public void threadExited(DebugThreadId threadId, DbgProcess proc, DbgCause cause) {
		DbgModelTargetProcess targetProcess = processesById.get(proc.getId());
		if (targetProcess != null) {
			targetProcess.getThreads().threadExited(threadId);
		}
	}

	@Override
	public void moduleLoaded(DbgProcess proc, String name, DbgCause cause) {
		DbgModelTargetProcess process = getTargetProcess(proc);
		process.getModules().libraryLoaded(name);
	}

	@Override
	public void moduleUnloaded(DbgProcess proc, String name, DbgCause cause) {
		DbgModelTargetProcess process = getTargetProcess(proc);
		process.getModules().libraryUnloaded(name);
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getManager().listProcesses().thenAccept(byIID -> {
			List<TargetObject> processes;
			synchronized (this) {
				processes = byIID.values()
						.stream()
						.map(this::getTargetProcess)
						.collect(Collectors.toList());
			}
			setElements(processes, Map.of(), "Refreshed");
		});
	}

	@Override
	public synchronized DbgModelTargetProcess getTargetProcess(DebugProcessId id) {
		return processesById.computeIfAbsent(id,
			i -> new DbgModelTargetProcessImpl(this, getManager().getKnownProcesses().get(id)));
	}

	@Override
	public synchronized DbgModelTargetProcess getTargetProcess(DbgProcess process) {
		return processesById.computeIfAbsent(process.getId(),
			i -> new DbgModelTargetProcessImpl(this, process));
	}

}
