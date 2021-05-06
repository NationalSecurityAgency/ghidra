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

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.manager.*;
import agent.dbgeng.model.iface1.DbgModelTargetConfigurable;
import agent.dbgeng.model.iface2.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.target.TargetConfigurable;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "ProcessContainer",
	elements = { //
		@TargetElementType(type = DbgModelTargetProcessImpl.class) //
	},
	attributes = { //
		@TargetAttributeType(name = TargetConfigurable.BASE_ATTRIBUTE_NAME, type = Integer.class), //
		@TargetAttributeType(type = Void.class) //
	},
	canonicalContainer = true)
public class DbgModelTargetProcessContainerImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetProcessContainer, DbgModelTargetConfigurable {

	public DbgModelTargetProcessContainerImpl(DbgModelTargetSession session) {
		super(session.getModel(), session, "Processes", "ProcessContainer");
		this.changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, 16), "Initialized");

		getManager().addEventsListener(this);
	}

	@Override
	public void processAdded(DbgProcess proc, DbgCause cause) {
		DbgModelTargetSession session = (DbgModelTargetSession) getParent();
		session.setAccessible(true);
		DbgModelTargetProcess process = getTargetProcess(proc);
		changeElements(List.of(), List.of(process), Map.of(), "Added");
		process.processStarted(proc.getPid());
		getListeners().fire.event(getProxy(), null, TargetEventType.PROCESS_CREATED,
			"Process " + proc.getId() + " started " + process.getName() + "pid=" + proc.getPid(),
			List.of(process));
	}

	@Override
	public void processStarted(DbgProcess proc, DbgCause cause) {
		DbgModelTargetProcess process = getTargetProcess(proc);
		process.processStarted(proc.getPid());
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
	public void moduleLoaded(DbgProcess proc, DebugModuleInfo info, DbgCause cause) {
		DbgModelTargetProcess process = getTargetProcess(proc);
		DbgModelTargetModuleContainer modules = process.getModules();
		if (modules != null) {
			modules.libraryLoaded(info.toString());
		}
		DbgModelTargetMemoryContainer memory = process.getMemory();
		if (memory != null) {
			memory.requestElements(false);
		}
	}

	@Override
	public void moduleUnloaded(DbgProcess proc, DebugModuleInfo info, DbgCause cause) {
		DbgModelTargetProcess process = getTargetProcess(proc);
		process.getModules().libraryUnloaded(info.toString());
		DbgModelTargetMemoryContainer memory = process.getMemory();
		if (memory != null) {
			memory.requestElements(false);
		}
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

}
