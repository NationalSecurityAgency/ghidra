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

import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.manager.*;
import agent.dbgeng.manager.reason.*;
import agent.dbgeng.model.iface2.*;
import ghidra.dbg.target.TargetObject;
import ghidra.util.datastruct.WeakValueHashMap;

// TODO: Should TargetThreadContainer be a thing?
public class DbgModelTargetThreadContainerImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetThreadContainer {

	protected final DbgProcess process;

	protected final Map<DebugThreadId, DbgModelTargetThreadImpl> threadsById =
		new WeakValueHashMap<>();

	public DbgModelTargetThreadContainerImpl(DbgModelTargetProcessImpl process) {
		super(process.getModel(), process, "Threads", "ThreadContainer");
		this.process = process.process;

		getManager().addEventsListener(this);
	}

	@Override
	public void threadCreated(DbgThread thread) {
		changeElements(List.of(), List.of(getTargetThread(thread)), Map.of(), "Created");
		DbgModelTargetThread targetThread = getTargetThread(thread);
		changeElements(List.of(), List.of(targetThread), Map.of(), "Created");
		targetThread.threadStateChanged(DbgState.STARTING, DbgReason.getReason(null));
		getListeners().fire(TargetEventScopeListener.class)
				.event(this, targetThread, TargetEventType.THREAD_CREATED,
					"Thread " + thread.getId() + " started", List.of(targetThread));
	}

	@Override
	public void threadStateChanged(DbgThread thread, DbgState state, DbgCause cause,
			DbgReason reason) {
		DbgModelTargetThread targetThread = getTargetThread(thread);
		targetThread.threadStateChanged(state, reason);
		TargetEventType eventType = getEventType(state, cause, reason);
		getListeners().fire(TargetEventScopeListener.class)
				.event(this, targetThread, eventType, "Thread " + thread.getId() + " state changed",
					List.of(targetThread));
	}

	@Override
	public void threadExited(DebugThreadId threadId) {
		DbgModelTargetThread targetThread = threadsById.get(threadId);
		if (targetThread != null) {
			getListeners().fire(TargetEventScopeListener.class)
					.event(this, targetThread, TargetEventType.THREAD_EXITED,
						"Thread " + threadId + " exited", List.of(targetThread));
		}
		synchronized (this) {
			threadsById.remove(threadId);
		}
		changeElements(List.of( //
			DbgModelTargetThreadImpl.indexThread(threadId) //
		), List.of(), Map.of(), "Exited");
	}

	private TargetEventType getEventType(DbgState state, DbgCause cause, DbgReason reason) {
		switch (state) {
			case RUNNING:
				return TargetEventType.RUNNING;
			case STOPPED:
			case EXIT:
				if (reason instanceof DbgEndSteppingRangeReason) {
					return TargetEventType.STEP_COMPLETED;
				}
				if (reason instanceof DbgSignalReceivedReason) {
					return TargetEventType.SIGNAL;
				}
				if (reason instanceof DbgExitedReason) {
					return TargetEventType.EXCEPTION;
				}
				if (reason instanceof DbgExitNormallyReason) {
					return TargetEventType.THREAD_EXITED;
				}
				return TargetEventType.STOPPED;
			default:
				break;
		}
		return null;
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return process.listThreads().thenAccept(byTID -> {
			List<TargetObject> threads;
			synchronized (this) {
				threads =
					byTID.values().stream().map(this::getTargetThread).collect(Collectors.toList());
			}
			setElements(threads, Map.of(), "Refreshed");
		});
	}

	@Override
	public synchronized DbgModelTargetThread getTargetThread(DbgThread thread) {
		return threadsById.computeIfAbsent(thread.getId(),
			i -> new DbgModelTargetThreadImpl(this, (DbgModelTargetProcess) parent, thread));
	}

}
