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
package ghidra.app.plugin.core.debug.gui.memview;

import java.util.*;

import ghidra.async.AsyncDebouncer;
import ghidra.async.AsyncTimer;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.program.model.address.*;
import ghidra.trace.model.*;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointManager;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.trace.util.TraceEvents;
import ghidra.util.Swing;

public class DebuggerMemviewTraceListener extends TraceDomainObjectListener {

	protected MemviewProvider provider;
	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	Trace currentTrace;

	private boolean trackTrace = false;
	private boolean trackThreads = true;
	private boolean trackRegions = true;
	private boolean trackModules = true;
	private boolean trackSections = true;
	private boolean trackBreakpoints = true;
	private boolean trackBytes = true;

	List<MemoryBox> updateList = new ArrayList<>();
	private final AsyncDebouncer<Void> updateLabelDebouncer =
		new AsyncDebouncer<>(AsyncTimer.DEFAULT_TIMER, 100);

	public DebuggerMemviewTraceListener(MemviewProvider provider) {
		this.provider = provider;

		updateLabelDebouncer.addListener(__ -> Swing.runIfSwingOrRunLater(() -> doUpdate()));

		listenFor(TraceEvents.THREAD_ADDED, this::threadChanged);
		listenFor(TraceEvents.THREAD_CHANGED, this::threadChanged);
		listenFor(TraceEvents.THREAD_LIFESPAN_CHANGED, this::threadChanged);
		listenFor(TraceEvents.THREAD_DELETED, this::threadChanged);

		listenFor(TraceEvents.REGION_ADDED, this::regionChanged);
		listenFor(TraceEvents.REGION_CHANGED, this::regionChanged);
		listenFor(TraceEvents.REGION_LIFESPAN_CHANGED, this::regionChanged);
		listenFor(TraceEvents.REGION_DELETED, this::regionChanged);

		listenFor(TraceEvents.MODULE_ADDED, this::moduleChanged);
		listenFor(TraceEvents.MODULE_CHANGED, this::moduleChanged);
		listenFor(TraceEvents.MODULE_LIFESPAN_CHANGED, this::moduleChanged);
		listenFor(TraceEvents.MODULE_DELETED, this::moduleChanged);

		listenFor(TraceEvents.SECTION_ADDED, this::sectionChanged);
		listenFor(TraceEvents.SECTION_CHANGED, this::sectionChanged);
		listenFor(TraceEvents.SECTION_DELETED, this::sectionChanged);

		listenFor(TraceEvents.BREAKPOINT_ADDED, this::breakpointChanged);
		listenFor(TraceEvents.BREAKPOINT_CHANGED, this::breakpointChanged);
		listenFor(TraceEvents.BREAKPOINT_LIFESPAN_CHANGED, this::breakpointChanged);
		listenFor(TraceEvents.BREAKPOINT_DELETED, this::breakpointChanged);

		listenFor(TraceEvents.BYTES_CHANGED, this::bytesChanged);
	}

	public MemviewProvider getProvider() {
		return provider;
	}

	protected AddressRange rng(AddressSpace space, long min, long max) {
		return new AddressRangeImpl(space.getAddress(min), space.getAddress(max));
	}

	private void threadChanged(TraceThread thread) {
		if (!trackThreads || !trackTrace) {
			return;
		}
		AddressFactory factory = thread.getTrace().getBaseAddressFactory();
		AddressSpace defaultSpace = factory.getDefaultAddressSpace();
		Long threadId = thread.getKey();
		AddressRange rng = rng(defaultSpace, threadId, threadId);
		MemoryBox box = new MemoryBox("Thread " + thread.getName(), MemviewBoxType.THREAD, rng,
			thread.getLifespan());
		updateList.add(box);
		updateLabelDebouncer.contact(null);
	}

	private void regionChanged(TraceMemoryRegion region) {
		if (!trackRegions || !trackTrace) {
			return;
		}
		MemoryBox box = new MemoryBox("Region " + region.getName(), MemviewBoxType.VIRTUAL_ALLOC,
			region.getRange(), region.getLifespan());
		updateList.add(box);
		updateLabelDebouncer.contact(null);
	}

	private void moduleChanged(TraceModule module) {
		if (!trackModules || !trackTrace) {
			return;
		}
		AddressRange range = module.getRange();
		if (range == null) {
			return;
		}
		MemoryBox box = new MemoryBox("Module " + module.getName(), MemviewBoxType.MODULE, range,
			module.getLifespan());
		updateList.add(box);
		updateLabelDebouncer.contact(null);
	}

	private void sectionChanged(TraceSection section) {
		if (!trackSections || !trackTrace) {
			return;
		}
		MemoryBox box = new MemoryBox("Section " + section.getName(), MemviewBoxType.IMAGE,
			section.getRange(), section.getModule().getLifespan());
		updateList.add(box);
		updateLabelDebouncer.contact(null);
	}

	private void breakpointChanged(TraceBreakpoint bpt) {
		if (!trackBreakpoints || !trackTrace) {
			return;
		}
		MemoryBox box = new MemoryBox("Breakpoint " + bpt.getName(), MemviewBoxType.BREAKPOINT,
			bpt.getRange(), bpt.getLifespan());
		updateList.add(box);
		updateLabelDebouncer.contact(null);
	}

	private void bytesChanged(TraceAddressSnapRange range) {
		if (!trackBytes || !trackTrace) {
			return;
		}
		Lifespan lifespan = range.getLifespan();
		MemoryBox box = new MemoryBox("BytesChanged " + range.description(),
			MemviewBoxType.WRITE_MEMORY, range.getRange(), lifespan);
		updateList.add(box);
		updateLabelDebouncer.contact(null);
	}

	private void doUpdate() {
		provider.addBoxes(updateList);
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
		if (current.equals(coordinates)) {
			current = coordinates;
			return;
		}
		boolean doListeners = !Objects.equals(current.getTrace(), coordinates.getTrace());
		if (doListeners) {
			removeListener();
		}
		current = coordinates;
		if (doListeners) {
			addListener();
		}
	}

	protected DebuggerCoordinates adjustCoordinates(DebuggerCoordinates coordinates) {
		// Because the view's snap is changing with or without us.... So go with.
		// i.e., take the time, but not the thread
		return current.time(coordinates.getTime());
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		//DebuggerCoordinates adjusted = adjustCoordinates(coordinates);
		setCoordinates(coordinates);
		Trace trace = coordinates.getTrace();
		if (trace != null) {
			Swing.runLater(new Runnable() {
				@Override
				public void run() {
					processTrace(trace);
				}
			});
		}
		else {
			provider.reset();
		}
	}

	public void traceClosed(Trace trace) {
		if (current.getTrace() == trace) {
			setCoordinates(DebuggerCoordinates.NOWHERE);
		}
	}

	public void toggleTrackTrace() {
		trackTrace = !trackTrace;
	}

	private void processTrace(Trace trace) {
		updateList.clear();
		provider.reset();
		if (!provider.isVisible()) {
			return;
		}
		TraceThreadManager threadManager = trace.getThreadManager();
		for (TraceThread thread : threadManager.getAllThreads()) {
			threadChanged(thread);
		}
		TraceModuleManager moduleManager = trace.getModuleManager();
		for (TraceModule module : moduleManager.getAllModules()) {
			moduleChanged(module);
			Collection<? extends TraceSection> sections = module.getSections();
			for (TraceSection section : sections) {
				sectionChanged(section);
			}
		}
		TraceMemoryManager memoryManager = trace.getMemoryManager();
		for (TraceMemoryRegion region : memoryManager.getAllRegions()) {
			regionChanged(region);
		}
		TraceBreakpointManager breakpointManager = trace.getBreakpointManager();
		for (TraceBreakpoint bpt : breakpointManager.getAllBreakpoints()) {
			breakpointChanged(bpt);
		}
		updateLabelDebouncer.contact(null);
	}

}
