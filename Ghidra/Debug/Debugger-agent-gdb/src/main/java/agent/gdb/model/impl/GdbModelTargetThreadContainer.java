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

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.gdb.manager.*;
import agent.gdb.manager.impl.cmd.GdbStateChangeRecord;
import agent.gdb.manager.reason.GdbBreakpointHitReason;
import ghidra.async.AsyncFence;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.util.Msg;

@TargetObjectSchemaInfo(
	name = "ThreadContainer",
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class GdbModelTargetThreadContainer
		extends DefaultTargetObject<GdbModelTargetThread, GdbModelTargetInferior> {
	public static final String NAME = "Threads";

	protected final GdbModelImpl impl;
	protected final GdbInferior inferior;

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

	public void threadExited(int threadId) {
		synchronized (this) {
			impl.deleteModelObject(threadId);
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
			for (Integer tid : inferior.getKnownThreads().keySet()) {
				if (!byTID.keySet().contains(tid)) {
					impl.deleteModelObject(byTID.get(tid));
				}
			}
			updateUsingThreads(byTID);
		});
	}

	public synchronized GdbModelTargetThread getTargetThread(GdbThread thread) {
		assert thread.getInferior() == inferior;
		TargetObject modelObject = impl.getModelObject(thread);
		if (modelObject != null) {
			return (GdbModelTargetThread) modelObject;
		}
		return new GdbModelTargetThread(this, parent, thread);
	}

	public synchronized GdbModelTargetThread getTargetThreadIfPresent(GdbThread thread) {
		return (GdbModelTargetThread) impl.getModelObject(thread);
	}

	protected void invalidateRegisterCaches() {
		for (GdbThread thread : inferior.getKnownThreads().values()) {
			GdbModelTargetThread targetThread = (GdbModelTargetThread) impl.getModelObject(thread);
			targetThread.invalidateRegisterCaches();
		}
	}

	public CompletableFuture<Void> stateChanged(GdbStateChangeRecord sco) {
		/**
		 * No sense refreshing anything unless we're stopped. Worse yet, because of fun timing
		 * issues, we often see RUNNING just a little late, since the callbacks are all issued on a
		 * separate thread. If that RUNNING is received after the manager has processed a
		 * =thread-exited, we will wind up invalidating that thread early.
		 */
		if (sco.getState() != GdbState.STOPPED) {
			return AsyncUtils.NIL;
		}
		return requestElements(false).thenCompose(__ -> {
			AsyncFence fence = new AsyncFence();
			for (GdbThread thread : inferior.getKnownThreads().values()) {
				GdbModelTargetThread targetThread =
					(GdbModelTargetThread) impl.getModelObject(thread);
				fence.include(targetThread.stateChanged(sco));
			}
			return fence.ready();
		}).exceptionally(__ -> {
			Msg.error(this, "Could not update threads " + this + " on STOPPED");
			return null;
		});
	}

	public GdbModelTargetBreakpointLocation breakpointHit(GdbBreakpointHitReason reason) {
		GdbThread thread = impl.gdb.getThread(reason.getThreadId());
		return getTargetThread(thread).breakpointHit(reason);
	}
}
