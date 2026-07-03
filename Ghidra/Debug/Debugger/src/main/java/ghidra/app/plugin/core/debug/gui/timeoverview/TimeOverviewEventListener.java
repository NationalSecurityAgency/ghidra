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
package ghidra.app.plugin.core.debug.gui.timeoverview;

import java.util.Objects;

import ghidra.app.plugin.core.debug.gui.timeoverview.timetype.TimeType;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.trace.model.*;
import ghidra.trace.model.bookmark.TraceBookmark;
import ghidra.trace.model.breakpoint.TraceBreakpointLocation;
import ghidra.trace.model.breakpoint.TraceBreakpointManager;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceModuleManager;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.trace.util.TraceEvents;
import ghidra.util.Swing;

public class TimeOverviewEventListener extends TraceDomainObjectListener {

	private TimeOverviewColorPlugin p;
	private DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;

	public TimeOverviewEventListener(TimeOverviewColorPlugin plugin) {

		this.p = plugin;

		listenForUntyped(DomainObjectEvent.RESTORED, this::objectRestored);

		listenFor(TraceEvents.THREAD_ADDED, this::threadAdded);
		listenFor(TraceEvents.THREAD_CHANGED, this::threadChanged);
		listenFor(TraceEvents.THREAD_LIFESPAN_CHANGED, this::threadChanged);
		listenFor(TraceEvents.THREAD_DELETED, this::threadDeleted);

		listenFor(TraceEvents.MODULE_ADDED, this::moduleAdded);
		listenFor(TraceEvents.MODULE_CHANGED, this::moduleChanged);
		listenFor(TraceEvents.MODULE_LIFESPAN_CHANGED, this::moduleChanged);
		listenFor(TraceEvents.MODULE_DELETED, this::moduleDeleted);

		listenFor(TraceEvents.REGION_ADDED, this::regionAdded);
		listenFor(TraceEvents.REGION_CHANGED, this::regionChanged);
		listenFor(TraceEvents.REGION_LIFESPAN_CHANGED, this::regionChanged);
		listenFor(TraceEvents.REGION_DELETED, this::regionDeleted);

		listenFor(TraceEvents.BREAKPOINT_ADDED, this::bptAdded);
		listenFor(TraceEvents.BREAKPOINT_CHANGED, this::bptChanged);
		listenFor(TraceEvents.BREAKPOINT_LIFESPAN_CHANGED, this::bptChanged);
		listenFor(TraceEvents.BREAKPOINT_DELETED, this::bptDeleted);

		listenFor(TraceEvents.BOOKMARK_ADDED, this::bookmarkAdded);
		listenFor(TraceEvents.BOOKMARK_CHANGED, this::bookmarkChanged);
		listenFor(TraceEvents.BOOKMARK_LIFESPAN_CHANGED, this::bookmarkChanged);
		listenFor(TraceEvents.BOOKMARK_DELETED, this::bookmarkDeleted);

	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		//DebuggerCoordinates adjusted = adjustCoordinates(coordinates);
		setCoordinates(coordinates);
		Trace trace = coordinates.getTrace();
		if (trace != null) {
			Swing.runLater(() -> processTrace(trace));
		}
	}

	protected void addListener() {
		Trace trace = current.getTrace();
		if (trace != null) {
			trace.addListener(this);
		}
	}

	protected void removeListener() {
		Trace trace = current.getTrace();
		if (trace != null) {
			trace.removeListener(this);
		}
	}

	public void setCoordinates(DebuggerCoordinates coordinates) {
		boolean doListeners = !Objects.equals(current.getTrace(), coordinates.getTrace());
		if (doListeners) {
			removeListener();
		}
		current = coordinates;
		if (doListeners) {
			addListener();
		}
	}

	private void processTrace(Trace trace) {
		//updateList.clear();
		TraceThreadManager threadManager = trace.getThreadManager();
		for (TraceThread thread : threadManager.getAllThreads()) {
			threadChanged(thread);
		}
		TraceModuleManager moduleManager = trace.getModuleManager();
		for (TraceModule module : moduleManager.getAllModules()) {
			moduleChanged(module);
		}
		TraceMemoryManager memoryManager = trace.getMemoryManager();
		for (TraceMemoryRegion region : memoryManager.getAllRegions()) {
			regionChanged(region);
		}
		TraceBreakpointManager breakpointManager = trace.getBreakpointManager();
		for (TraceBreakpointLocation bpt : breakpointManager.getAllBreakpointLocations()) {
			bptChanged(bpt);
		}
	}

	private void threadAdded(TraceThread thread) {
		TraceObject obj = thread.getObject();
		obj.getOrderedValues(Lifespan.ALL, TraceBreakpointLocation.KEY_RANGE, true)
				.forEach(v -> {
					long snap = v.getMinSnap();
					p.updateMap(snap, TimeType.BPT_ADDED, thread.getName(snap), true);
				});
	}

	private void threadChanged(TraceThread thread) {
		TraceObject obj = thread.getObject();
		obj.getOrderedValues(Lifespan.ALL, TraceThread.KEY_TID, true).forEach(v -> {
			long snapMin = v.getMinSnap();
			long snapMax = v.getMaxSnap();
			if (snapMin == snapMax) {
				p.updateMap(snapMin, TimeType.THREAD_CHANGED, thread.getName(snapMin),
					true);
			}
			else {
				p.updateMap(snapMin, TimeType.THREAD_ADDED, thread.getName(snapMin), true);
				p.updateMap(snapMax, TimeType.THREAD_REMOVED, thread.getName(snapMax),
					true);
			}
		});
	}

	private void threadDeleted(TraceThread thread) {
		TraceObject obj = thread.getObject();
		obj.getOrderedValues(Lifespan.ALL, TraceBreakpointLocation.KEY_RANGE, true)
				.forEach(v -> {
					long snap = v.getMaxSnap();
					p.updateMap(snap, TimeType.THREAD_REMOVED, thread.getName(snap), true);
				});
	}

	private void moduleAdded(TraceModule module) {
		TraceObject obj = module.getObject();
		obj.getOrderedValues(Lifespan.ALL, TraceBreakpointLocation.KEY_RANGE, true)
				.forEach(v -> {
					long snap = v.getMinSnap();
					p.updateMap(snap, TimeType.MODULE_ADDED, module.getName(snap), true);
				});
	}

	private void moduleChanged(TraceModule module) {
		TraceObject obj = module.getObject();
		obj.getOrderedValues(Lifespan.ALL, TraceBreakpointLocation.KEY_RANGE, true)
				.forEach(v -> {
					long snapMin = v.getMinSnap();
					long snapMax = v.getMaxSnap();
					if (snapMin == snapMax) {
						p.updateMap(snapMin, TimeType.MODULE_CHANGED, module.getName(snapMin),
							true);
					}
					else {
						p.updateMap(snapMin, TimeType.MODULE_ADDED, module.getName(snapMin), true);
						p.updateMap(snapMax, TimeType.MODULE_REMOVED, module.getName(snapMax),
							true);
					}
				});
	}

	private void moduleDeleted(TraceModule module) {
		TraceObject obj = module.getObject();
		obj.getOrderedValues(Lifespan.ALL, TraceBreakpointLocation.KEY_RANGE, true)
				.forEach(v -> {
					long snap = v.getMaxSnap();
					p.updateMap(snap, TimeType.MODULE_REMOVED, module.getName(snap), true);
				});
	}

	private void regionAdded(TraceMemoryRegion region) {
		TraceObject obj = region.getObject();
		obj.getOrderedValues(Lifespan.ALL, TraceBreakpointLocation.KEY_RANGE, true)
				.forEach(v -> {
					long snap = v.getMinSnap();
					p.updateMap(snap, TimeType.REGION_ADDED, region.getName(snap), true);
				});
	}

	private void regionChanged(TraceMemoryRegion region) {
		TraceObject obj = region.getObject();
		obj.getOrderedValues(Lifespan.ALL, TraceBreakpointLocation.KEY_RANGE, true)
				.forEach(v -> {
					long snapMin = v.getMinSnap();
					long snapMax = v.getMaxSnap();
					if (snapMin == snapMax) {
						p.updateMap(snapMin, TimeType.REGION_CHANGED, region.getName(snapMin),
							true);
					}
					else {
						p.updateMap(snapMin, TimeType.REGION_ADDED, region.getName(snapMin), true);
						p.updateMap(snapMax, TimeType.REGION_REMOVED, region.getName(snapMax),
							true);
					}
				});
	}

	private void regionDeleted(TraceMemoryRegion region) {
		TraceObject obj = region.getObject();
		obj.getOrderedValues(Lifespan.ALL, TraceBreakpointLocation.KEY_RANGE, true)
				.forEach(v -> {
					long snap = v.getMaxSnap();
					p.updateMap(snap, TimeType.REGION_REMOVED, region.getName(snap), true);
				});
	}

	private void bptAdded(TraceBreakpointLocation bpt) {
		TraceObject obj = bpt.getObject();
		obj.getOrderedValues(Lifespan.ALL, TraceBreakpointLocation.KEY_RANGE, true)
				.forEach(v -> {
					long snap = v.getMinSnap();
					p.updateMap(snap, TimeType.BPT_ADDED, bpt.getName(snap), true);
				});
	}

	private void bptChanged(TraceBreakpointLocation bpt) {
		TraceObject obj = bpt.getObject();
		obj.getOrderedValues(Lifespan.ALL, TraceBreakpointLocation.KEY_RANGE, true)
				.forEach(v -> {
					long snapMin = v.getMinSnap();
					long snapMax = v.getMaxSnap();
					if (snapMin == snapMax) {
						p.updateMap(snapMin, TimeType.BPT_CHANGED, bpt.getName(snapMin), true);
					}
					else {
						p.updateMap(snapMin, TimeType.BPT_ADDED, bpt.getName(snapMin), true);
						p.updateMap(snapMax, TimeType.BPT_REMOVED, bpt.getName(snapMax), true);
					}
				});
	}

	private void bptDeleted(TraceBreakpointLocation bpt) {
		TraceObject obj = bpt.getObject();
		obj.getOrderedValues(Lifespan.ALL, TraceBreakpointLocation.KEY_RANGE, true)
				.forEach(v -> {
					long snap = v.getMaxSnap();
					p.updateMap(snap, TimeType.BPT_REMOVED, bpt.getName(snap), true);
				});
	}

	private void bookmarkAdded(TraceBookmark bookmark) {
		long snap = bookmark.getLifespan().lmin();
		p.updateMap(snap, TimeType.BOOKMARK_ADDED, bookmark.getComment(), true);
	}

	private void bookmarkChanged(TraceBookmark bookmark) {
		long snapMin = bookmark.getLifespan().lmin();
		p.updateMap(snapMin, TimeType.BOOKMARK_CHANGED, bookmark.getComment(), false);
	}

	private void bookmarkDeleted(TraceBookmark bookmark) {
		long snap = bookmark.getLifespan().lmax();
		p.updateMap(snap, TimeType.BOOKMARK_REMOVED, bookmark.getComment(), true);
	}

	private void objectRestored(DomainObjectChangeRecord domainobjectchangerecord1) {
		p.updateMap();
	}

}
