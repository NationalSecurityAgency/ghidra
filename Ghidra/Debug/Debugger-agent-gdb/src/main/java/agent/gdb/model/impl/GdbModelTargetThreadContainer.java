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
package agent.gdb.model.impl;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.gdb.manager.*;
import agent.gdb.manager.reason.GdbReason;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(name = "ThreadContainer", attributes = {
	@TargetAttributeType(type = Void.class)
}, canonicalContainer = true)
public class GdbModelTargetThreadContainer
		extends DefaultTargetObject<GdbModelTargetThread, GdbModelTargetInferior> {
	public static final String NAME = "Threads";

	protected final GdbModelImpl impl;
	protected final GdbInferior inferior;

	protected final Map<Integer, GdbModelTargetThread> threadsById = new WeakValueHashMap<>();

	public GdbModelTargetThreadContainer(GdbModelTargetInferior inferior) {
		super(inferior.impl, inferior, NAME, "ThreadContainer");
		this.impl = inferior.impl;
		this.inferior = inferior.inferior;
	}

	public GdbModelTargetThread threadCreated(GdbThread thread) {
		// TODO: Can I get a better reason?
		GdbModelTargetThread targetThread = getTargetThread(thread);
		changeElements(List.of(), List.of(targetThread), "Created");
		return targetThread;
	}

	public void threadStateChanged(GdbThread thread, GdbState state, GdbReason reason) {
		getTargetThread(thread).threadStateChanged(state, reason);
	}

	public void threadsStateChanged(Collection<? extends GdbThread> threads, GdbState state,
			GdbReason reason) {
		for (GdbThread thread : threads) {
			threadStateChanged(thread, state, reason);
		}
	}

	public void threadExited(int threadId) {
		synchronized (this) {
			threadsById.remove(threadId);
		}
		changeElements(List.of(GdbModelTargetThread.indexThread(threadId)), List.of(), "Exited");
	}

	protected void updateUsingThreads(Map<Integer, GdbThread> byTID) {
		List<GdbModelTargetThread> threads;
		synchronized (this) {
			threads =
				byTID.values().stream().map(this::getTargetThread).collect(Collectors.toList());
		}
		setElements(threads, "Refreshed");
	}

	@Override
	protected CompletableFuture<Void> requestElements(boolean refresh) {
		if (!refresh) {
			updateUsingThreads(inferior.getKnownThreads());
			return AsyncUtils.NIL;
		}
		return inferior.listThreads().thenAccept(byTID -> {
			threadsById.keySet().retainAll(byTID.keySet());
			updateUsingThreads(byTID);
		});
	}

	public synchronized GdbModelTargetThread getTargetThread(GdbThread thread) {
		return threadsById.computeIfAbsent(thread.getId(),
			i -> new GdbModelTargetThread(this, parent, thread));
	}

	public synchronized GdbModelTargetThread getTargetThreadIfPresent(int threadId) {
		return threadsById.get(threadId);
	}

	protected void invalidateRegisterCaches() {
		for (GdbModelTargetThread thread : threadsById.values()) {
			thread.invalidateRegisterCaches();
		}
	}
}
