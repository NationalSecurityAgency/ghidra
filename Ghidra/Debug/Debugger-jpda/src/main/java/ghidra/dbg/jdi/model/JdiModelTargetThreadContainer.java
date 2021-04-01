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
package ghidra.dbg.jdi.model;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import com.sun.jdi.ThreadReference;

import ghidra.async.AsyncFence;
import ghidra.dbg.jdi.manager.*;
import ghidra.dbg.jdi.model.iface1.JdiModelTargetEventScope;
import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.schema.*;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "ThreadContainer",
	elements = {
		@TargetElementType(type = JdiModelTargetThread.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class JdiModelTargetThreadContainer extends JdiModelTargetObjectImpl
		implements JdiModelTargetEventScope, JdiEventsListenerAdapter {

	private List<ThreadReference> threads;

	protected final Map<String, JdiModelTargetThread> threadsById = new WeakValueHashMap<>();

	public JdiModelTargetThreadContainer(JdiModelTargetObject object, String name,
			List<ThreadReference> threads) {
		super(object, name);
		this.threads = threads;

		if (targetVM != null) {
			impl.getManager().addEventsListener(targetVM.vm, this);
		}

	}

	public JdiModelTargetThread threadCreated(ThreadReference thread) {
		JdiModelTargetThread targetThread = getTargetThread(thread);
		changeElements(List.of(), List.of(targetThread), Map.of(), "Created");
		return targetThread;
	}

	public void threadExited(ThreadReference thread) {
		synchronized (this) {
			threadsById.remove(thread.name());
		}
		changeElements(List.of(thread.name()), List.of(), Map.of(), "Exited");
	}

	@Override
	public void threadStateChanged(ThreadReference thread, Integer state, JdiCause cause,
			JdiReason reason) {
		JdiModelTargetThread targetThread = getTargetThread(thread);
		TargetExecutionState targetState = targetThread.convertState(state);
		targetThread.threadStateChanged(targetState);
		TargetEventType eventType = getEventType(reason);
		getListeners().fire.event(this, targetThread, eventType,
			"Thread " + targetThread.getName() + " state changed", List.of(targetThread));
	}

	private TargetEventType getEventType(JdiReason reason) {
		if (reason == JdiReason.Reasons.STEP) {
			return TargetEventType.STEP_COMPLETED;
		}
		if (reason == JdiReason.Reasons.BREAKPOINT_HIT) {
			return TargetEventType.BREAKPOINT_HIT;
		}
		if (reason == JdiReason.Reasons.ACCESS_WATCHPOINT_HIT) {
			return TargetEventType.BREAKPOINT_HIT;
		}
		if (reason == JdiReason.Reasons.WATCHPOINT_HIT) {
			return TargetEventType.BREAKPOINT_HIT;
		}
		if (reason == JdiReason.Reasons.INTERRUPT) {
			return TargetEventType.SIGNAL;
		}
		if (reason == JdiReason.Reasons.RESUMED) {
			return TargetEventType.RUNNING;
		}
		return TargetEventType.STOPPED;
	}

	protected CompletableFuture<Void> updateUsingThreads(List<ThreadReference> refs) {
		List<JdiModelTargetThread> targetThreads;
		synchronized (this) {
			targetThreads = refs.stream().map(this::getTargetThread).collect(Collectors.toList());
		}
		AsyncFence fence = new AsyncFence();
		for (JdiModelTargetThread t : targetThreads) {
			fence.include(t.init());
		}
		return fence.ready().thenAccept(__ -> {
			setElements(targetThreads, Map.of(), "Refreshed");
		});
	}

	@Override
	protected CompletableFuture<Void> requestElements(boolean refresh) {
		return updateUsingThreads(threads);
	}

	public synchronized JdiModelTargetThread getTargetThread(ThreadReference thread) {
		return threadsById.computeIfAbsent(thread.name(),
			i -> (JdiModelTargetThread) getInstance(thread));
	}

	public synchronized JdiModelTargetThread getTargetThreadIfPresent(String name) {
		return threadsById.get(name);
	}

}
