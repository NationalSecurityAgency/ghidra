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
package agent.lldb.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import SWIG.*;
import agent.lldb.lldb.DebugClient;
import agent.lldb.lldb.DebugModuleInfo;
import agent.lldb.manager.LldbCause;
import agent.lldb.manager.LldbReason;
import agent.lldb.model.iface1.LldbModelTargetConfigurable;
import agent.lldb.model.iface2.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.target.TargetConfigurable;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "ProcessContainer",
	elements = { //
		@TargetElementType(type = LldbModelTargetProcessImpl.class) //
	},
	attributes = { //
		@TargetAttributeType(name = TargetConfigurable.BASE_ATTRIBUTE_NAME, type = Integer.class), //
		@TargetAttributeType(type = Void.class) //
	},
	canonicalContainer = true)
public class LldbModelTargetProcessContainerImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetProcessContainer, LldbModelTargetConfigurable {

	private LldbModelTargetSessionImpl session;

	public LldbModelTargetProcessContainerImpl(LldbModelTargetSessionImpl session) {
		super(session.getModel(), session, "Processes", "ProcessContainer");
		this.session = session;
		this.changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, 16), "Initialized");

		getManager().addEventsListener(this);
	}

	@Override
	public void processAdded(SBProcess proc, LldbCause cause) {
		LldbModelTargetSession session = (LldbModelTargetSession) getParent();
		SBTarget parentTarget = (SBTarget) session.getModelObject();
		SBTarget procTarget = proc.GetTarget();
		if (!DebugClient.getId(parentTarget).equals(DebugClient.getId(procTarget))) {
			return;
		}
		session.setAccessible(true);
		LldbModelTargetProcess process = getTargetProcess(proc);
		changeElements(List.of(), List.of(process), Map.of(), "Added");
		process.processStarted(proc);
		getListeners().fire.event(getProxy(), null, TargetEventType.PROCESS_CREATED,
			"Process " + DebugClient.getId(proc) + " started " + process.getName(),
			List.of(process));
	}

	@Override
	public void processReplaced(SBProcess proc, LldbCause cause) {
		LldbModelTargetSession session = (LldbModelTargetSession) getParent();
		session.setAccessible(true);
		LldbModelTargetProcess process = getTargetProcess(proc);
		changeElements(List.of(), List.of(process), Map.of(), "Added");
	}

	@Override
	public void processStarted(SBProcess proc, LldbCause cause) {
		LldbModelTargetProcess process = getTargetProcess(proc);
		process.processStarted(proc);
	}

	@Override
	public void processRemoved(String processId, LldbCause cause) {
		changeElements(List.of( //
			processId //
		), List.of(), Map.of(), "Removed");
	}

	@Override
	public void threadCreated(SBThread thread, LldbCause cause) {
		LldbModelTargetProcess process = getTargetProcess(thread.GetProcess());
		LldbModelTargetThreadContainer threads = process.getThreads();
		if (threads != null) {
			threads.threadCreated(thread);
		}
	}

	@Override
	public void threadReplaced(SBThread thread, LldbCause cause) {
		LldbModelTargetProcess process = getTargetProcess(thread.GetProcess());
		process.getThreads().threadReplaced(thread);
	}

	@Override
	public void threadStateChanged(SBThread thread, StateType state, LldbCause cause,
			LldbReason reason) {
		LldbModelTargetProcess process = getTargetProcess(thread.GetProcess());
		process.threadStateChanged(thread, state, cause, reason);
	}

	@Override
	public void threadExited(SBThread thread, SBProcess proc, LldbCause cause) {
		LldbModelTargetProcess process = getTargetProcess(proc);
		if (process != null) {
			process.getThreads().threadExited(thread);
		}
	}

	@Override
	public void moduleLoaded(SBProcess proc, DebugModuleInfo info, int index, LldbCause cause) {
		LldbModelTargetModuleContainer modules = session.getModules();
		if (modules != null) {
			modules.libraryLoaded(info, index);
		}
	}

	@Override
	public void moduleUnloaded(SBProcess proc, DebugModuleInfo info, int index, LldbCause cause) {
		LldbModelTargetModuleContainer modules = session.getModules();
		if (modules != null) {
			modules.libraryUnloaded(info, index);
		}
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getManager().listProcesses(session.getSession()).thenAccept(byIID -> {
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
	public synchronized LldbModelTargetProcess getTargetProcess(SBProcess process) {
		TargetObject targetObject = getMapObject(process);
		if (targetObject != null) {
			LldbModelTargetProcess targetProcess = (LldbModelTargetProcess) targetObject;
			targetProcess.setModelObject(process);
			return targetProcess;
		}
		return new LldbModelTargetProcessImpl(this, process);
	}

	@Override
	public CompletableFuture<Void> writeConfigurationOption(String key, Object value) {
		switch (key) {
			case BASE_ATTRIBUTE_NAME:
				if (value instanceof Integer) {
					this.changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, value),
						"Modified");
					for (TargetObject child : getCachedElements().values()) {
						if (child instanceof LldbModelTargetProcessImpl) {
							LldbModelTargetProcessImpl targetProcess =
								(LldbModelTargetProcessImpl) child;
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
