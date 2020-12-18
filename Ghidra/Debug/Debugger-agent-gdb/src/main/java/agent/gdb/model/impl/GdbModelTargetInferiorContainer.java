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
import agent.gdb.manager.reason.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetEventScope.TargetEventScopeListener;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetExecutionStateful;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.util.Msg;
import ghidra.util.datastruct.WeakValueHashMap;

public class GdbModelTargetInferiorContainer
		extends DefaultTargetObject<GdbModelTargetInferior, GdbModelTargetSession>
		implements GdbEventsListenerAdapter {
	protected final GdbModelImpl impl;

	protected final Map<Integer, GdbModelTargetInferior> inferiorsById = new WeakValueHashMap<>();

	public GdbModelTargetInferiorContainer(GdbModelTargetSession session) {
		super(session.impl, session, "Inferiors", "InferiorContainer");
		this.impl = session.impl;

		impl.gdb.addEventsListener(this);
	}

	@Override
	public void inferiorAdded(GdbInferior inferior, GdbCause cause) {
		GdbModelTargetInferior inf = getTargetInferior(inferior);
		changeElements(List.of(), List.of(inf), "Added");
	}

	@Override
	public void inferiorStarted(GdbInferior inf, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(inf);
		// TODO: Move PROCESS_CREATED here to restore proper order of event reporting
		// Pending some client-side changes to handle architecture selection, though.
		inferior.inferiorStarted(inf.getPid()).thenAccept(__ -> {
			parent.getListeners()
					.fire(TargetEventScopeListener.class)
					.event(
						parent, null, TargetEventType.PROCESS_CREATED, "Inferior " + inf.getId() +
							" started " + inf.getExecutable() + " pid=" + inf.getPid(),
						List.of(inferior));
		}).exceptionally(ex -> {
			Msg.error(this, "Could not notify inferior started", ex);
			return null;
		});
	}

	@Override
	public void inferiorExited(GdbInferior inf, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(inf);
		parent.getListeners()
				.fire(TargetEventScopeListener.class)
				.event(parent, null, TargetEventType.PROCESS_EXITED,
					"Inferior " + inf.getId() + " exited code=" + inf.getExitCode(),
					List.of(inferior));
		inferior.inferiorExited(inf.getExitCode());
	}

	@Override
	public void inferiorRemoved(int inferiorId, GdbCause cause) {
		synchronized (this) {
			inferiorsById.remove(inferiorId);
		}
		changeElements(List.of(GdbModelTargetInferior.indexInferior(inferiorId)), List.of(),
			"Removed");
	}

	protected void gatherThreads(List<? super GdbModelTargetThread> into,
			GdbModelTargetInferior inferior, Collection<? extends GdbThread> from) {
		for (GdbThread t : from) {
			GdbModelTargetThread p = inferior.threads.getTargetThread(t);
			if (p != null) {
				into.add(p);
			}
		}
	}

	@Override
	public void inferiorStateChanged(GdbInferior inf, Collection<GdbThread> threads, GdbState state,
			GdbThread thread, GdbCause cause, GdbReason reason) {
		// Desired order of updates:
		//   1. TargetEvent emitted
		//   2. Thread states/stacks updated
		//   3. Memory regions updated (Ew)
		GdbModelTargetInferior inferior = getTargetInferior(inf);
		GdbModelTargetThread targetThread =
			thread == null ? null : inferior.threads.getTargetThread(thread);
		if (state == GdbState.RUNNING) {
			inferior.changeAttributes(List.of(), Map.of( //
				TargetExecutionStateful.STATE_ATTRIBUTE_NAME, TargetExecutionState.RUNNING //
			), reason.desc());
			List<Object> params = new ArrayList<>();
			gatherThreads(params, inferior, threads);
			parent.getListeners()
					.fire(TargetEventScopeListener.class)
					.event(parent, targetThread, TargetEventType.RUNNING, "Running", params);
		}
		if (state != GdbState.STOPPED) {
			inferior.threads.threadsStateChanged(threads, state, reason);
			return;
		}
		if (reason instanceof GdbBreakpointHitReason) {
			GdbBreakpointHitReason bptHit = (GdbBreakpointHitReason) reason;
			List<Object> params = new ArrayList<>();
			GdbModelTargetBreakpointSpec spec =
				parent.breakpoints.getTargetBreakpointSpecIfPresent(bptHit.getBreakpointId());
			if (spec != null) {
				params.add(spec);
			}
			gatherThreads(params, inferior, threads);
			parent.getListeners()
					.fire(TargetEventScopeListener.class)
					.event(parent, targetThread, TargetEventType.BREAKPOINT_HIT, bptHit.desc(),
						params);
		}
		else if (reason instanceof GdbEndSteppingRangeReason) {
			List<Object> params = new ArrayList<>();
			gatherThreads(params, inferior, threads);
			parent.getListeners()
					.fire(TargetEventScopeListener.class)
					.event(parent, targetThread, TargetEventType.STEP_COMPLETED, reason.desc(),
						params);
		}
		else if (reason instanceof GdbSignalReceivedReason) {
			GdbSignalReceivedReason signal = (GdbSignalReceivedReason) reason;
			List<Object> params = new ArrayList<>();
			params.add(signal.getSignalName());
			gatherThreads(params, inferior, threads);
			parent.getListeners()
					.fire(TargetEventScopeListener.class)
					.event(parent, targetThread, TargetEventType.SIGNAL, reason.desc(), params);
		}
		else {
			List<Object> params = new ArrayList<>();
			gatherThreads(params, inferior, threads);
			parent.getListeners()
					.fire(TargetEventScopeListener.class)
					.event(parent, targetThread, TargetEventType.STOPPED, reason.desc(), params);
		}
		// This will update stacks of newly-STOPPED threads
		inferior.changeAttributes(List.of(), Map.of( //
			TargetExecutionStateful.STATE_ATTRIBUTE_NAME, TargetExecutionState.STOPPED //
		), reason.desc());
		inferior.threads.threadsStateChanged(threads, state, reason);
		// Ew. I wish I didn't have to, but there doesn't seem to be a "(un)mapped" event
		inferior.updateMemory();
	}

	@Override
	public void threadCreated(GdbThread thread, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(thread.getInferior());
		GdbModelTargetThread targetThread = inferior.threads.threadCreated(thread);
		parent.getListeners()
				.fire(TargetEventScopeListener.class)
				.event(parent, targetThread, TargetEventType.THREAD_CREATED,
					"Thread " + thread.getId() + " started", List.of(targetThread));
	}

	@Override
	public void threadExited(int threadId, GdbInferior inf, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(inf);
		GdbModelTargetThread targetThread = inferior.threads.getTargetThreadIfPresent(threadId);
		parent.getListeners()
				.fire(TargetEventScopeListener.class)
				.event(parent, targetThread, TargetEventType.THREAD_EXITED,
					"Thread " + threadId + " exited", List.of(targetThread));
		inferior.threads.threadExited(threadId);
	}

	@Override
	public void libraryLoaded(GdbInferior inf, String name, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(inf);
		GdbModelTargetModule module = inferior.modules.libraryLoaded(name);
		parent.getListeners()
				.fire(TargetEventScopeListener.class)
				.event(parent, null, TargetEventType.MODULE_LOADED, "Library " + name + " loaded",
					List.of(module));
	}

	@Override
	public void libraryUnloaded(GdbInferior inf, String name, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(inf);
		GdbModelTargetModule module = inferior.modules.getTargetModuleIfPresent(name);
		parent.getListeners()
				.fire(TargetEventScopeListener.class)
				.event(parent, null, TargetEventType.MODULE_UNLOADED,
					"Library " + name + " unloaded", List.of(module));
		inferior.modules.libraryUnloaded(name);
	}

	@Override
	public void memoryChanged(GdbInferior inf, long addr, int len, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(inf);
		inferior.memory.memoryChanged(addr, len);
	}

	private void updateUsingInferiors(Map<Integer, GdbInferior> byIID) {
		List<GdbModelTargetInferior> inferiors;
		synchronized (this) {
			inferiors =
				byIID.values().stream().map(this::getTargetInferior).collect(Collectors.toList());
		}
		setElements(inferiors, "Refreshed");
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		if (!refresh) {
			updateUsingInferiors(impl.gdb.getKnownInferiors());
			return AsyncUtils.NIL;
		}
		return impl.gdb.listInferiors().thenAccept(this::updateUsingInferiors);
	}

	// NOTE: Does no good to override fetchElement
	// Cache should be kept in sync all the time, anyway

	public synchronized GdbModelTargetInferior getTargetInferior(int id) {
		return inferiorsById.computeIfAbsent(id,
			i -> new GdbModelTargetInferior(this, impl.gdb.getKnownInferiors().get(id)));
	}

	public synchronized GdbModelTargetInferior getTargetInferior(GdbInferior inferior) {
		GdbModelTargetInferior modelInferior = inferiorsById.get(inferior.getId());
		if (modelInferior != null) {
			modelInferior.updateDisplayAttribute();
		}
		else {
			modelInferior = new GdbModelTargetInferior(this, inferior);
			inferiorsById.put(inferior.getId(), modelInferior);
		}
		return modelInferior;
	}

	protected void invalidateMemoryAndRegisterCaches() {
		for (GdbModelTargetInferior inf : inferiorsById.values()) {
			inf.invalidateMemoryAndRegisterCaches();
		}
	}
}
