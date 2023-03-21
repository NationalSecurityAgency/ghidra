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

import java.lang.invoke.MethodHandles;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.dbgeng.dbgeng.DebugModuleInfo;
import agent.dbgeng.dbgeng.DebugProcessId;
import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.manager.DbgCause;
import agent.dbgeng.manager.DbgProcess;
import agent.dbgeng.manager.DbgReason;
import agent.dbgeng.manager.DbgState;
import agent.dbgeng.manager.DbgThread;
import agent.dbgeng.manager.breakpoint.DbgBreakpointInfo;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.iface1.DbgModelTargetConfigurable;
import agent.dbgeng.model.iface2.DbgModelTargetMemoryContainer;
import agent.dbgeng.model.iface2.DbgModelTargetModuleContainer;
import agent.dbgeng.model.iface2.DbgModelTargetProcess;
import agent.dbgeng.model.iface2.DbgModelTargetProcessContainer;
import agent.dbgeng.model.iface2.DbgModelTargetSession;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.target.TargetConfigurable;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetMethod.AnnotatedTargetMethod;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "ProcessContainer",
	elements = {
		@TargetElementType(type = DbgModelTargetProcessImpl.class)
	},
	attributes = {
		@TargetAttributeType(name = TargetConfigurable.BASE_ATTRIBUTE_NAME, type = Integer.class),
		@TargetAttributeType(name = "Populate", type = TargetMethod.class),
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class DbgModelTargetProcessContainerImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetProcessContainer, DbgModelTargetConfigurable {

	public DbgModelTargetProcessContainerImpl(DbgModelTargetSession session) {
		super(session.getModel(), session, "Processes", "ProcessContainer");
		this.changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, 16), "Initialized");

		DbgManagerImpl manager = getManager();
		manager.addEventsListener(this);
	}

	@Override
	public void processAdded(DbgProcess proc, DbgCause cause) {
		DbgModelTargetSession session = (DbgModelTargetSession) getParent();
		session.setAccessible(true);
		DbgModelTargetProcess process = getTargetProcess(proc);
		changeElements(List.of(), List.of(process), Map.of(), "Added");
		process.processStarted(Long.valueOf(proc.getPid()));
		broadcast().event(getProxy(), null, TargetEventType.PROCESS_CREATED,
			"Process " + proc.getId() + " started " + process.getName() + "pid=" + proc.getPid(),
			List.of(process));

		DbgManagerImpl manager = getManager();
		if (manager.isKernelMode()) {
			changeAttributes(List.of(), List.of(),
					AnnotatedTargetMethod.collectExports(MethodHandles.lookup(), getModel(), this),
					"Methods");
		}	
}

	@Override
	public void processStarted(DbgProcess proc, DbgCause cause) {
		DbgModelTargetProcess process = getTargetProcess(proc);
		process.processStarted(Long.valueOf(proc.getPid()));
	}

	@Override
	public void processRemoved(DebugProcessId processId, DbgCause cause) {
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
		process.threadStateChangedSpecific(thread, state);
	}

	@Override
	public void threadExited(DebugThreadId threadId, DbgProcess proc, DbgCause cause) {
		DbgModelTargetProcess process = getTargetProcess(proc);
		if (process != null) {
			process.getThreads().threadExited(threadId);
		}
	}

	@Override
	public void breakpointHit(DbgBreakpointInfo info, DbgCause cause) {
		DbgProcess proc = info.getProc();
		DbgModelTargetProcess process = getTargetProcess(proc);
		DbgModelTargetMemoryContainer memory = process.getMemory();
		if (memory != null) {
			memory.requestElements(RefreshBehavior.REFRESH_ALWAYS);
		}
	}

	@Override
	public void moduleLoaded(DbgProcess proc, DebugModuleInfo info, DbgCause cause) {
		DbgModelTargetProcess process = getTargetProcess(proc);
		DbgModelTargetModuleContainer modules = process.getModules();
		if (modules != null) {
			modules.libraryLoaded(info.toString());
		}
		DbgModelTargetMemoryContainer memory = process.getMemory();
		if (memory != null) {
			memory.requestElements(RefreshBehavior.REFRESH_ALWAYS);
		}
	}

	@Override
	public void moduleUnloaded(DbgProcess proc, DebugModuleInfo info, DbgCause cause) {
		DbgModelTargetProcess process = getTargetProcess(proc);
		process.getModules().libraryUnloaded(info.toString());
		DbgModelTargetMemoryContainer memory = process.getMemory();
		if (memory != null) {
			memory.requestElements(RefreshBehavior.REFRESH_NEVER);
		}
	}

	@Override
	public CompletableFuture<Void> requestElements(RefreshBehavior refresh) {
		DbgManagerImpl manager = getManager();
		return manager.listProcesses().thenAccept(byIID -> {
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
		DbgModelImpl impl = (DbgModelImpl) model;
		TargetObject modelObject = impl.getModelObject(id);
		if (modelObject != null) {
			return (DbgModelTargetProcess) modelObject;
		}
		return new DbgModelTargetProcessImpl(this, getManager().getKnownProcesses().get(id));
	}

	@Override
	public synchronized DbgModelTargetProcess getTargetProcess(DbgProcess process) {
		DbgModelImpl impl = (DbgModelImpl) model;
		TargetObject modelObject = impl.getModelObject(process);
		if (modelObject != null) {
			return (DbgModelTargetProcess) modelObject;
		}
		return new DbgModelTargetProcessImpl(this, process);
	}

	@Override
	public CompletableFuture<Void> writeConfigurationOption(String key, Object value) {
		switch (key) {
			case BASE_ATTRIBUTE_NAME:
				if (value instanceof Integer) {
					this.changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, value),
						"Modified");
					for (TargetObject child : getCachedElements().values()) {
						if (child instanceof DbgModelTargetProcessImpl) {
							DbgModelTargetProcessImpl targetProcess =
								(DbgModelTargetProcessImpl) child;
							targetProcess.setBase(value);
						}
					}
				}
				else {
					throw new DebuggerIllegalArgumentException("Base should be numeric");
				}
			default:
		}
		return AsyncUtils.NIL;
	}

	@TargetMethod.Export("Populate")
	public CompletableFuture<Void> populate() {
		return getManager().listOSProcesses().thenAccept(byPID -> {
			List<TargetObject> processes;
			synchronized (this) {
				processes =
					byPID.values().stream().map(this::getTargetProcess).collect(Collectors.toList());
			}
			setElements(processes, Map.of(), "Refreshed");
		});
	}
}
