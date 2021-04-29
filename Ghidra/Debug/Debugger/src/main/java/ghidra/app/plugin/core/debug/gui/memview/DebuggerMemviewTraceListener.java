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

import com.google.common.collect.Range;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.services.TraceRecorder;
import ghidra.async.AsyncDebouncer;
import ghidra.async.AsyncTimer;
import ghidra.program.model.address.*;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.*;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointManager;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.util.Swing;

public class DebuggerMemviewTraceListener extends TraceDomainObjectListener {

	protected MemviewProvider provider;
	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	Trace currentTrace;
	TraceRecorder currentRecorder;

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

		listenFor(TraceThreadChangeType.ADDED, this::threadChanged);
		listenFor(TraceThreadChangeType.CHANGED, this::threadChanged);
		listenFor(TraceThreadChangeType.LIFESPAN_CHANGED, this::threadChanged);
		listenFor(TraceThreadChangeType.DELETED, this::threadChanged);

		listenFor(TraceMemoryRegionChangeType.ADDED, this::regionChanged);
		listenFor(TraceMemoryRegionChangeType.CHANGED, this::regionChanged);
		listenFor(TraceMemoryRegionChangeType.LIFESPAN_CHANGED, this::regionChanged);
		listenFor(TraceMemoryRegionChangeType.DELETED, this::regionChanged);

		listenFor(TraceModuleChangeType.ADDED, this::moduleChanged);
		listenFor(TraceModuleChangeType.CHANGED, this::moduleChanged);
		listenFor(TraceModuleChangeType.LIFESPAN_CHANGED, this::moduleChanged);
		listenFor(TraceModuleChangeType.DELETED, this::moduleChanged);

		listenFor(TraceSectionChangeType.ADDED, this::sectionChanged);
		listenFor(TraceSectionChangeType.CHANGED, this::sectionChanged);
		listenFor(TraceSectionChangeType.DELETED, this::sectionChanged);

		listenFor(TraceBreakpointChangeType.ADDED, this::breakpointChanged);
		listenFor(TraceBreakpointChangeType.CHANGED, this::breakpointChanged);
		listenFor(TraceBreakpointChangeType.LIFESPAN_CHANGED, this::breakpointChanged);
		listenFor(TraceBreakpointChangeType.DELETED, this::breakpointChanged);

		listenFor(TraceMemoryBytesChangeType.CHANGED, this::bytesChanged);
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
		Range<Long> lifespan = range.getLifespan();
		Range<Long> newspan = Range.closedOpen(lifespan.lowerEndpoint(), lifespan.lowerEndpoint());
		MemoryBox box = new MemoryBox("BytesChanged " + range.description(),
			MemviewBoxType.WRITE_MEMORY, range.getRange(), newspan);
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
		return current.withSnap(coordinates.getSnap());
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
