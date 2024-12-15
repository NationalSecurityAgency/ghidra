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

import java.util.Collection;
import java.util.Set;

import ghidra.app.plugin.core.debug.service.model.interfaces.ManagedBreakpointRecorder;
import ghidra.dbg.target.*;
import ghidra.dbg.util.PathUtils;
import ghidra.debug.api.model.TraceRecorder;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

@Deprecated(forRemoval = true, since = "11.3")
public class DefaultBreakpointRecorder implements ManagedBreakpointRecorder {

	protected static String nameBreakpoint(TargetBreakpointLocation bpt) {
		if (bpt instanceof TargetBreakpointSpec) {
			return bpt.getIndex();
		}
		return bpt.getSpecification().getIndex() + "." + bpt.getIndex();
	}

	private final DefaultTraceRecorder recorder;
	private final Trace trace;
	private final TraceBreakpointManager breakpointManager;

	protected TargetBreakpointSpecContainer breakpointContainer;

	public DefaultBreakpointRecorder(DefaultTraceRecorder recorder) {
		this.recorder = recorder;
		this.trace = recorder.getTrace();
		this.breakpointManager = trace.getBreakpointManager();
	}

	@Override
	public void offerBreakpointContainer(TargetBreakpointSpecContainer bc) {
		if (breakpointContainer != null) {
			Msg.warn(this, "Already have a breakpoint container for this process");
		}
		breakpointContainer = bc;
	}

	@Override
	public void offerBreakpointLocation(TargetObject containerParent,
			TargetBreakpointLocation bpt) {
		synchronized (this) {
			if (recorder.getMemoryMapper() == null) {
				return;
			}
		}
		RecorderBreakpointLocationResolver resolver =
			new RecorderBreakpointLocationResolver(recorder, bpt);
		resolver.updateBreakpoint(containerParent, bpt);
	}

	protected void doRecordBreakpoint(long snap, TargetBreakpointLocation loc,
			Set<TraceThread> traceThreads) {
		synchronized (this) {
			if (recorder.getMemoryMapper() == null) {
				throw new IllegalStateException(
					"No memory mapper! Have not recorded a region, yet.");
			}
		}
		String path = PathUtils.toString(loc.getPath());
		String name = nameBreakpoint(loc);
		AddressRange traceRange = recorder.getMemoryMapper().targetToTrace(loc.getRange());
		try {
			TargetBreakpointSpec spec = loc.getSpecification();
			boolean enabled = spec.isEnabled();
			Set<TraceBreakpointKind> traceKinds =
				TraceRecorder.targetToTraceBreakpointKinds(spec.getKinds());
			TraceBreakpoint traceBpt =
				breakpointManager.placeBreakpoint(path, snap,
					traceRange, traceThreads, traceKinds, enabled, spec.getExpression());
			traceBpt.setName(name);
		}
		catch (DuplicateNameException e) {
			Msg.error(this, "Could not record placed breakpoint: " + e);
		}
	}

	@Override
	public void recordBreakpoint(TargetBreakpointLocation loc,
			Set<TraceThread> traceThreads) {
		String path = loc.getJoinedPath(".");
		long snap = recorder.getSnap();
		recorder.parTx.execute("Breakpoint " + path + " placed", () -> {
			doRecordBreakpoint(snap, loc, traceThreads);
		}, path);
	}

	protected void doRemoveBreakpointLocation(long snap, TargetBreakpointLocation loc) {
		String path = loc.getJoinedPath(".");
		for (TraceBreakpoint traceBpt : breakpointManager.getBreakpointsByPath(path)) {
			try {
				if (traceBpt.getPlacedSnap() > snap) {
					Msg.error(this,
						"Tracked, now removed breakpoint was placed in the future? " + path);
				}
				else if (traceBpt.getPlacedSnap() == snap) {
					// TODO: I forget if this is allowed for DBTrace iteration
					traceBpt.delete();
				}
				else {
					traceBpt.setClearedSnap(snap - 1);
				}
			}
			catch (DuplicateNameException e) {
				Msg.error(this, "Could not record breakpoint removal: " + e);
			}
		}
	}

	@Override
	public void removeBreakpointLocation(TargetBreakpointLocation loc) {
		String path = loc.getJoinedPath(".");
		long snap = recorder.getSnap();
		recorder.parTx.execute("Breakpoint " + path + " deleted", () -> {
			doRemoveBreakpointLocation(snap, loc);
		}, path);
	}

	protected void doBreakpointLocationChanged(long snap, AddressRange traceRng, String path) {
		for (TraceBreakpoint traceBpt : breakpointManager.getBreakpointsByPath(path)) {
			if (traceBpt.getRange().equals(traceRng)) {
				continue; // Nothing to change
			}
			// TODO: Verify all other attributes match?
			try {
				if (traceBpt.getPlacedSnap() == snap) {
					traceBpt.delete();
				}
				else {
					traceBpt.setClearedSnap(snap - 1);
				}
				TraceBreakpoint newtraceBpt =
					breakpointManager.placeBreakpoint(path, snap, traceRng,
						traceBpt.getThreads(), traceBpt.getKinds(), traceBpt.isEnabled(snap),
						traceBpt.getComment());
				// placeBreakpoint resets the name - maybe pass name in?
				newtraceBpt.setName(traceBpt.getName());

			}
			catch (DuplicateNameException e) {
				// Split, and length matters not
				Msg.error(this, "Could not record breakpoint length change: " + e);
			}
		}
	}

	@Override
	public void breakpointLocationChanged(AddressRange traceRng, String path)
			throws AssertionError {
		long snap = recorder.getSnap();
		recorder.parTx.execute("Breakpoint length changed", () -> {
			doBreakpointLocationChanged(snap, traceRng, path);
		}, path);
	}

	protected void doBreakpointSpecChanged(long snap,
			Collection<? extends TargetBreakpointLocation> bpts, boolean enabled,
			Collection<TraceBreakpointKind> kinds) {
		for (TargetBreakpointLocation bl : bpts) {
			String path = PathUtils.toString(bl.getPath());
			recorder.parTx.execute("Breakpoint " + path + " changed", () -> {
				TraceBreakpoint traceBpt = recorder.getTraceBreakpoint(bl);
				if (traceBpt == null) {
					Msg.warn(this, "Cannot find toggled trace breakpoint for " + path);
					return;
				}
				// Verify attributes match? Eh. If they don't, someone has fiddled with it.
				traceBpt.splitAndSet(snap, enabled, kinds);
			}, path);
		}
	}

	@Override
	public void breakpointSpecChanged(TargetBreakpointSpec spec, boolean enabled,
			Collection<TraceBreakpointKind> kinds) {
		long snap = recorder.getSnap();
		spec.getLocations().thenAccept(bpts -> {
			doBreakpointSpecChanged(snap, bpts, enabled, kinds);
		}).exceptionally(ex -> {
			Msg.error(this, "Error recording changed breakpoint spec: " + spec.getJoinedPath("."),
				ex);
			return null;
		});
	}

	@Override
	public TraceBreakpoint getTraceBreakpoint(TargetBreakpointLocation bpt) {
		String path = PathUtils.toString(bpt.getPath());
		return breakpointManager.getPlacedBreakpointByPath(recorder.getSnap(), path);
	}

	@Override
	public TargetBreakpointSpecContainer getBreakpointContainer() {
		return breakpointContainer;
	}
}
