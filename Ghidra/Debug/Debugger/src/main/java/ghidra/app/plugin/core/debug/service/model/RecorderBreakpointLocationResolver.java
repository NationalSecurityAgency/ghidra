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
package ghidra.app.plugin.core.debug.service.model;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.app.plugin.core.debug.service.model.interfaces.ManagedThreadRecorder;
import ghidra.async.AsyncFence;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.target.*;
import ghidra.dbg.util.PathUtils;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;

public class RecorderBreakpointLocationResolver {
	// TODO: I'm not sure this class really offers anything anymore

	private DefaultTraceRecorder recorder;
	private final TargetBreakpointLocation bpt;
	private final TargetBreakpointSpec spec;
	private boolean affectsProcess = false;
	private final Set<TraceThread> threadsAffected = new LinkedHashSet<>();

	public RecorderBreakpointLocationResolver(DefaultTraceRecorder recorder,
			TargetBreakpointLocation bpt) {
		this.recorder = recorder;
		this.bpt = bpt;
		this.spec = bpt.getSpecification();
	}

	// TODO: This is a stopgap, since Location.getAffects is removed
	// Do we really need to worry about per-thread breakpoints?
	static Collection<TargetObject> getAffects(TargetBreakpointLocation bpt) {
		TargetObject findProc = bpt;
		while (!(findProc instanceof TargetProcess)) {
			findProc = findProc.getParent();
		}
		return List.of(findProc);
	}

	private CompletableFuture<Void> resolve(TargetObject obj) {
		AsyncFence fence = new AsyncFence();
		if (obj.equals(recorder.getTarget())) {
			affectsProcess = true;
		}
		else {
			fence.include(resolveThread(obj));
		}
		return fence.ready();
	}

	// TODO: If affects is empty/null, also try to default to the containing process
	private CompletableFuture<Void> resolveThread(TargetObject ref) {
		return DebugModelConventions.findThread(ref).thenAccept(thread -> {
			if (thread == null) {
				Msg.error(this,
					"Could not find process or thread from breakpoint-affected object: " + ref);
				return;
			}
			if (!ref.equals(thread)) {
				Msg.warn(this, "Effective breakpoint should apply to process or threads. Got " +
					ref + ". Resolved to " + thread);
				return;
			}
			if (!PathUtils.isAncestor(recorder.getTarget().getPath(), thread.getPath())) {
				/**
				 * Perfectly normal if the breakpoint container is outside the process container.
				 * Don't record such in this trace, though.
				 */
				return;
			}
			ManagedThreadRecorder rec = recorder.getThreadRecorder(thread); //listenerForRecord.getOrCreateThreadRecorder(thread);
			synchronized (threadsAffected) {
				threadsAffected.add(rec.getTraceThread());
			}
		}).exceptionally(ex -> {
			Msg.error(this, "Error resolving thread from breakpoint-affected object: " + ref);
			return null;
		});
	}

	public void updateBreakpoint(TargetObject containerParent, TargetBreakpointLocation loc) {
		resolve(containerParent).thenAccept(__ -> {
			if (affectsProcess || !threadsAffected.isEmpty()) {
				recorder.breakpointRecorder.recordBreakpoint(loc, threadsAffected);
			}
		}).exceptionally(ex -> {
			Msg.error(this, "Could record target breakpoint: " + loc, ex);
			return null;
		});
	}

}
