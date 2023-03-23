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
package agent.frida.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.frida.frida.*;
import agent.frida.manager.*;
import agent.frida.model.iface1.FridaModelTargetConfigurable;
import agent.frida.model.iface2.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.target.TargetConfigurable;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "ProcessContainer",
	elements = { //
		@TargetElementType(type = FridaModelTargetProcessImpl.class) //
	},
	attributes = { //
		@TargetAttributeType(name = TargetConfigurable.BASE_ATTRIBUTE_NAME, type = Integer.class), //
		@TargetAttributeType(type = Void.class) //
	},
	canonicalContainer = true)
public class FridaModelTargetProcessContainerImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetProcessContainer, FridaModelTargetConfigurable {

	private FridaModelTargetSessionImpl session;

	public FridaModelTargetProcessContainerImpl(FridaModelTargetSessionImpl session) {
		super(session.getModel(), session, "Processes", "ProcessContainer");
		this.session = session;
		this.changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, 16), "Initialized");

		getManager().addEventsListener(this);
	}

	@Override
	public void processAdded(FridaProcess proc, FridaCause cause) {
		FridaSession parentSession = (FridaSession) session.getModelObject();
		FridaSession procSession = proc.getSession();
		if (!FridaClient.getId(parentSession).equals(FridaClient.getId(procSession))) {
			return;
		}
		session.setAccessible(true);
		FridaModelTargetProcess process = getTargetProcess(proc);
		changeElements(List.of(), List.of(process), Map.of(), "Added");
		process.processStarted(proc);
		broadcast().event(getProxy(), null, TargetEventType.PROCESS_CREATED,
			"Process " + FridaClient.getId(proc) + " started " + process.getName(),
			List.of(process));
	}

	@Override
	public void processReplaced(FridaProcess proc, FridaCause cause) {
		session.setAccessible(true);
		FridaModelTargetProcess process = getTargetProcess(proc);
		changeElements(List.of(), List.of(process), Map.of(), "Added");
	}

	@Override
	public void processStarted(FridaProcess proc, FridaCause cause) {
		FridaModelTargetProcess process = getTargetProcess(proc);
		process.processStarted(proc);
	}

	@Override
	public void processRemoved(String processId, FridaCause cause) {
		changeElements(List.of( //
			processId //
		), List.of(), Map.of(), "Removed");
	}

	/*
	@Override
	public void threadStateChanged(FridaThread thread, FridaState state, FridaCause cause,
			FridaReason reason) {
		FridaModelTargetProcess process = getTargetProcess(thread.getProcess());
		process.threadStateChanged(thread, state, cause, reason);
	}
	*/

	@Override
	public CompletableFuture<Void> requestElements(RefreshBehavior refresh) {
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
	public synchronized FridaModelTargetProcess getTargetProcess(FridaProcess process) {
		TargetObject targetObject = getMapObject(process);
		if (targetObject != null) {
			FridaModelTargetProcess targetProcess = (FridaModelTargetProcess) targetObject;
			targetProcess.setModelObject(process);
			return targetProcess;
		}
		return new FridaModelTargetProcessImpl(this, process);
	}

	@Override
	public CompletableFuture<Void> writeConfigurationOption(String key, Object value) {
		switch (key) {
			case BASE_ATTRIBUTE_NAME:
				if (value instanceof Integer) {
					this.changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, value),
						"Modified");
					for (TargetObject child : getCachedElements().values()) {
						if (child instanceof FridaModelTargetProcessImpl) {
							FridaModelTargetProcessImpl targetProcess =
								(FridaModelTargetProcessImpl) child;
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
