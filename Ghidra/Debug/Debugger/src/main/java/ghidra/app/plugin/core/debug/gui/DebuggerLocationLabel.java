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
package ghidra.app.plugin.core.debug.gui;

import java.awt.event.MouseEvent;
import java.util.*;

import javax.swing.JLabel;

import org.apache.commons.collections4.ComparatorUtils;

import docking.ActionContext;
import docking.ComponentProvider;
import ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionActionContext;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerModuleActionContext;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerSectionActionContext;
import ghidra.async.AsyncDebouncer;
import ghidra.async.AsyncTimer;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.program.model.address.Address;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceSection;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.util.TraceEvents;
import ghidra.util.Swing;

public class DebuggerLocationLabel extends JLabel {

	protected class ForLocationLabelTraceListener extends TraceDomainObjectListener {
		private final AsyncDebouncer<Void> updateLabelDebouncer =
			new AsyncDebouncer<>(AsyncTimer.DEFAULT_TIMER, 100);

		public ForLocationLabelTraceListener() {
			updateLabelDebouncer
					.addListener(__ -> Swing.runIfSwingOrRunLater(() -> doUpdateLabel()));

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
		}

		private void doUpdateLabel() {
			updateLabel();
		}

		private void regionChanged(TraceMemoryRegion region) {
			updateLabelDebouncer.contact(null);
		}

		private void moduleChanged(TraceModule module) {
			updateLabelDebouncer.contact(null);
		}

		private void sectionChanged(TraceSection section) {
			updateLabelDebouncer.contact(null);
		}
	}

	protected final ForLocationLabelTraceListener listener = new ForLocationLabelTraceListener();

	private DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	private Address address = null;

	protected boolean sameCoordinates(DebuggerCoordinates a, DebuggerCoordinates b) {
		if (!Objects.equals(a.getView(), b.getView())) {
			return false; // Subsumes trace
		}
		if (!Objects.equals(a.getTime(), b.getTime())) {
			return false;
		}
		return true;
	}

	protected void addNewListeners() {
		Trace trace = current.getTrace();
		if (trace != null) {
			trace.addListener(listener);
		}
	}

	protected void removeOldListeners() {
		Trace trace = current.getTrace();
		if (trace != null) {
			trace.removeListener(listener);
		}
	}

	public void goToCoordinates(DebuggerCoordinates coordinates) {
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}
		boolean doListeners = !Objects.equals(current.getTrace(), coordinates.getTrace());
		if (doListeners) {
			removeOldListeners();
		}
		current = coordinates;
		if (doListeners) {
			addNewListeners();
		}
		updateLabel();
	}

	public void goToAddress(Address address) {
		this.address = address;
		updateLabel();
	}

	protected TraceSection getNearestSectionContaining() {
		if (current.getView() == null) {
			return null;
		}
		Trace trace = current.getTrace();
		List<TraceSection> sections =
			new ArrayList<>(trace.getModuleManager().getSectionsAt(current.getSnap(), address));
		if (sections.isEmpty()) {
			return null;
		}
		long snap = current.getSnap();
		/**
		 * TODO: DB's R-Tree could probably do this natively. Not sure it's an optimization, though,
		 * since few, if any, overlapping sections are expected.
		 */
		sections.sort(ComparatorUtils.chainedComparator(List.of(
			Comparator.comparing(s -> s.getRange(snap).getMinAddress()),
			Comparator.comparing(s -> -s.getRange(snap).getLength()))));
		return sections.get(sections.size() - 1);
	}

	protected TraceModule getNearestModuleContaining() {
		if (current.getView() == null) {
			return null;
		}
		Trace trace = current.getTrace();
		List<TraceModule> modules =
			new ArrayList<>(trace.getModuleManager().getModulesAt(current.getSnap(), address));
		if (modules.isEmpty()) {
			return null;
		}
		long snap = current.getSnap();
		// TODO: DB's R-Tree could probably do this natively
		modules.sort(ComparatorUtils.chainedComparator(List.of(
			Comparator.comparing(m -> m.getRange(snap).getMinAddress()),
			Comparator.comparing(m -> -m.getRange(snap).getLength()))));
		return modules.get(modules.size() - 1);
	}

	protected TraceMemoryRegion getRegionContaining() {
		if (current.getView() == null) {
			return null;
		}
		Trace trace = current.getTrace();
		return trace.getMemoryManager().getRegionContaining(current.getSnap(), address);
	}

	protected String computeLocationString() {
		TraceProgramView view = current.getView();
		if (view == null) {
			return "";
		}
		if (address == null) {
			return "(nowhere)";
		}
		long snap = current.getSnap();
		try {
			TraceSection section = getNearestSectionContaining();
			if (section != null) {
				return section.getModule().getName(snap) + ":" + section.getName(snap);
			}
			TraceModule module = getNearestModuleContaining();
			if (module != null) {
				return module.getName(snap);
			}
			TraceMemoryRegion region = getRegionContaining();
			if (region != null) {
				return region.getName(snap);
			}
			return "(unknown)";
		}
		catch (Throwable t) {
			return "(error) " + t.getMessage();
		}
	}

	public void updateLabel() {
		String label = computeLocationString();
		setText(label);
		setToolTipText(label);
	}

	public ActionContext getActionContext(ComponentProvider provider, MouseEvent event) {
		TraceProgramView view = current.getView();
		if (view == null) {
			return null;
		}
		if (address == null) {
			return null;
		}
		try {
			TraceSection section = getNearestSectionContaining();
			if (section != null) {
				return new DebuggerSectionActionContext(provider, Set.of(section), this, true);
			}
			TraceModule module = getNearestModuleContaining();
			if (module != null) {
				return new DebuggerModuleActionContext(provider, Set.of(module), this, true);
			}
			TraceMemoryRegion region = getRegionContaining();
			if (region != null) {
				return new DebuggerRegionActionContext(provider, Set.of(region), this, true);
			}
			return null;
		}
		catch (Throwable t) {
			// The error should already be displayed in the label
			return null;
		}
	}
}
