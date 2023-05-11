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

import agent.frida.frida.FridaClient;
import agent.frida.manager.*;
import agent.frida.model.iface1.FridaModelTargetConfigurable;
import agent.frida.model.iface2.*;
import agent.frida.model.methods.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.target.TargetConfigurable;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;

@TargetObjectSchemaInfo(
	name = "ThreadContainer",
	elementResync = ResyncMode.ALWAYS,
	elements = { //
		@TargetElementType(type = FridaModelTargetThreadImpl.class) //
	},
	attributes = { //
		@TargetAttributeType(name = TargetConfigurable.BASE_ATTRIBUTE_NAME, type = Integer.class), //
		@TargetAttributeType(type = Object.class) //
	},
	canonicalContainer = true)
public class FridaModelTargetThreadContainerImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetThreadContainer, FridaModelTargetConfigurable {

	protected final FridaProcess process;
	private FridaModelTargetThreadSleepImpl sleep;
	private FridaModelTargetThreadStalkImpl stalk;
	private FridaModelTargetUnloadScriptImpl unload;

	public FridaModelTargetThreadContainerImpl(FridaModelTargetProcessImpl process) {
		super(process.getModel(), process, "Threads", "ThreadContainer");
		this.process = process.getProcess();
		this.changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, 16), "Initialized");

		this.sleep = new FridaModelTargetThreadSleepImpl(this);
		this.stalk = new FridaModelTargetThreadStalkImpl(this);
		this.unload = new FridaModelTargetUnloadScriptImpl(this, stalk.getName());
		this.changeAttributes(List.of(), List.of( //
			sleep, //
			stalk, //
			unload //
		), Map.of(), "Initialized");

		getManager().addEventsListener(this);
		// NB: Asking for threads on 32-bit Android targets will kill the server right now
		//requestElements(true);
	}

	@Override
	public void threadCreated(FridaThread thread, FridaCause cause) {
		changeElements(List.of(), List.of(getTargetThread(thread)), Map.of(), "Created");
		FridaModelTargetThread targetThread = getTargetThread(thread);
		changeElements(List.of(), List.of(targetThread), Map.of(), "Created");
		targetThread.threadStateChangedSpecific(FridaState.FRIDA_THREAD_UNINTERRUPTIBLE,
			FridaReason.getReason(null));
		broadcast().event(getProxy(), targetThread, TargetEventType.THREAD_CREATED,
			"Thread " + FridaClient.getId(thread) + " started", List.of(targetThread));
	}

	@Override
	public void threadReplaced(FridaThread thread, FridaCause cause) {
		changeElements(List.of(), List.of(getTargetThread(thread)), Map.of(), "Created");
		FridaModelTargetThread targetThread = getTargetThread(thread);
		changeElements(List.of(), List.of(targetThread), Map.of(), "Created");
	}

	@Override
	public void threadExited(FridaThread thread, FridaCause cause) {
		if (thread == null) {
			return;
		}
		String threadId = FridaModelTargetThreadImpl.indexThread(thread);
		FridaModelTargetThread targetThread = (FridaModelTargetThread) getMapObject(thread);
		if (targetThread != null) {
			broadcast().event(getProxy(), targetThread, TargetEventType.THREAD_EXITED,
				"Thread " + threadId + " exited", List.of(targetThread));
		}
		changeElements(List.of( //
			threadId //
		), List.of(), Map.of(), "Exited");
	}

	@Override
	public void threadStateChanged(FridaThread thread, FridaState state, FridaCause cause,
			FridaReason reason) {
		FridaModelTargetThread targetThread = getTargetThread(thread);
		TargetEventType eventType = getEventType(state, cause, reason);
		broadcast().event(getProxy(), targetThread, eventType,
			"Thread " + FridaClient.getId(thread) + " state changed", List.of(targetThread));
		targetThread.threadStateChangedSpecific(state, reason);
	}

	private TargetEventType getEventType(FridaState state, FridaCause cause, FridaReason reason) {
		switch (state) {
			case FRIDA_THREAD_WAITING:
				return TargetEventType.RUNNING;
			case FRIDA_THREAD_HALTED:
				return TargetEventType.PROCESS_EXITED;
			case FRIDA_THREAD_UNINTERRUPTIBLE:
				return TargetEventType.PROCESS_CREATED;
			case FRIDA_THREAD_STOPPED:
				return TargetEventType.STOPPED;
			case FRIDA_THREAD_RUNNING:
				return TargetEventType.RUNNING;
			default:
				return TargetEventType.STOPPED;
		}
	}

	@Override
	public CompletableFuture<Void> requestElements(RefreshBehavior refresh) {
		if (refresh.equals(RefreshBehavior.REFRESH_ALWAYS)) {
			broadcast().invalidateCacheRequested(this);
		}
		return getManager().listThreads(process);
	}

	@Override
	public synchronized FridaModelTargetThread getTargetThread(FridaThread thread) {
		TargetObject targetObject = getMapObject(thread);
		if (targetObject != null) {
			FridaModelTargetThread targetThread = (FridaModelTargetThread) targetObject;
			targetThread.setModelObject(thread);
			return targetThread;
		}
		return new FridaModelTargetThreadImpl(this, (FridaModelTargetProcess) parent, thread);
	}

	@Override
	public CompletableFuture<Void> writeConfigurationOption(String key, Object value) {
		switch (key) {
			case BASE_ATTRIBUTE_NAME:
				if (value instanceof Integer) {
					this.changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, value),
						"Modified");
					for (TargetObject child : getCachedElements().values()) {
						if (child instanceof FridaModelTargetThreadImpl) {
							FridaModelTargetThreadImpl targetThread =
								(FridaModelTargetThreadImpl) child;
							targetThread.setBase(value);
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
