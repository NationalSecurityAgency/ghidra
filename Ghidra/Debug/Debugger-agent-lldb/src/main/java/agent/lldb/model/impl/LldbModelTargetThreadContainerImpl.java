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
import agent.lldb.manager.LldbCause;
import agent.lldb.manager.LldbReason;
import agent.lldb.model.iface1.LldbModelTargetConfigurable;
import agent.lldb.model.iface2.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.target.TargetConfigurable;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;

@TargetObjectSchemaInfo(
	name = "ThreadContainer",
	elementResync = ResyncMode.ALWAYS,
	elements = { //
		@TargetElementType(type = LldbModelTargetThreadImpl.class) //
	},
	attributes = { //
		@TargetAttributeType(name = TargetConfigurable.BASE_ATTRIBUTE_NAME, type = Integer.class), //
		@TargetAttributeType(type = Void.class) //
	},
	canonicalContainer = true)
public class LldbModelTargetThreadContainerImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetThreadContainer, LldbModelTargetConfigurable {

	protected final SBProcess process;

	public LldbModelTargetThreadContainerImpl(LldbModelTargetProcessImpl process) {
		super(process.getModel(), process, "Threads", "ThreadContainer");
		this.process = process.getProcess();
		this.changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, 16), "Initialized");

		getManager().addEventsListener(this);
		requestElements(false);
	}

	@Override
	public void threadCreated(SBThread thread) {
		changeElements(List.of(), List.of(getTargetThread(thread)), Map.of(), "Created");
		LldbModelTargetThread targetThread = getTargetThread(thread);
		changeElements(List.of(), List.of(targetThread), Map.of(), "Created");
		targetThread.threadStateChangedSpecific(StateType.eStateConnected,
			LldbReason.getReason(null));
		getListeners().fire.event(getProxy(), targetThread, TargetEventType.THREAD_CREATED,
			"Thread " + DebugClient.getId(thread) + " started", List.of(targetThread));
	}

	@Override
	public void threadReplaced(SBThread thread) {
		changeElements(List.of(), List.of(getTargetThread(thread)), Map.of(), "Created");
		LldbModelTargetThread targetThread = getTargetThread(thread);
		changeElements(List.of(), List.of(targetThread), Map.of(), "Created");
	}

	@Override
	public void threadStateChanged(SBThread thread, StateType state, LldbCause cause,
			LldbReason reason) {
		LldbModelTargetThread targetThread = getTargetThread(thread);
		TargetEventType eventType = getEventType(state, cause, reason);
		getListeners().fire.event(getProxy(), targetThread, eventType,
			"Thread " + DebugClient.getId(thread) + " state changed", List.of(targetThread));
		targetThread.threadStateChangedSpecific(state, reason);
	}

	@Override
	public void threadExited(SBThread thread) {
		String threadId = LldbModelTargetThreadImpl.indexThread(thread);
		LldbModelTargetThread targetThread = (LldbModelTargetThread) getMapObject(thread);
		if (targetThread != null) {
			getListeners().fire.event(getProxy(), targetThread, TargetEventType.THREAD_EXITED,
				"Thread " + threadId + " exited", List.of(targetThread));
		}
		changeElements(List.of( //
			threadId //
		), List.of(), Map.of(), "Exited");
	}

	// TODO?: Serive a more complete event set from this?
	private TargetEventType getEventType(StateType state, LldbCause cause, LldbReason reason) {
		switch (state.swigValue()) {
			case 0:	// eStateInvalid
				return TargetEventType.RUNNING;
			case 1: // eStateUnloaded
				return TargetEventType.PROCESS_EXITED;
			case 2: // eStateConnected
			case 3: // eStateAttaching
			case 4: // eStateLaunching
				return TargetEventType.PROCESS_CREATED;
			case 5: // eStateStopped
				return TargetEventType.STOPPED;
			case 6: // eStateRunning
			case 7: // eStateStepping
				return TargetEventType.RUNNING;
			case 8:  // eStateCrashed
			case 9:  // eStateDetached
			case 10: // eStateExited
				return TargetEventType.PROCESS_EXITED;
			case 11: // eStateSuspended
				return TargetEventType.STOPPED;
			default:
				return TargetEventType.STOPPED;
		}
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getManager().listThreads(process).thenAccept(byTID -> {
			List<TargetObject> threads;
			synchronized (this) {
				threads =
					byTID.values().stream().map(this::getTargetThread).collect(Collectors.toList());
			}
			setElements(threads, Map.of(), "Refreshed");
		});
	}

	@Override
	public synchronized LldbModelTargetThread getTargetThread(SBThread thread) {
		TargetObject targetObject = getMapObject(thread);
		if (targetObject != null) {
			LldbModelTargetThread targetThread = (LldbModelTargetThread) targetObject;
			targetThread.setModelObject(thread);
			return targetThread;
		}
		return new LldbModelTargetThreadImpl(this, (LldbModelTargetProcess) parent, thread);
	}

	@Override
	public CompletableFuture<Void> writeConfigurationOption(String key, Object value) {
		switch (key) {
			case BASE_ATTRIBUTE_NAME:
				if (value instanceof Integer) {
					this.changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, value),
						"Modified");
					for (TargetObject child : getCachedElements().values()) {
						if (child instanceof LldbModelTargetThreadImpl) {
							LldbModelTargetThreadImpl targetThread =
								(LldbModelTargetThreadImpl) child;
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
