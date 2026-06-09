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
package ghidra.app.plugin.core.debug.gui.breakpoint.timeline;

import java.awt.BorderLayout;
import java.util.*;

import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import generic.theme.GIcon;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.lifecycle.Internal;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.symbol.RefType;
import ghidra.trace.model.*;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.symbol.TraceReference;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.util.TraceEvents;

public class BreakpointTimelineProvider extends ComponentProvider {
	record BreakpointHitEvent(long snap, TraceBreakpointKind breakType, String breakpointName) {}

	private class BreakpointTimeOverviewEventListener extends TraceDomainObjectListener {

		public BreakpointTimeOverviewEventListener() {
			listenFor(TraceEvents.BREAKPOINT_CHANGED, this::breakpointChanged);
			listenFor(TraceEvents.BREAKPOINT_DELETED, this::breakpointDeleted);
			listenFor(TraceEvents.SNAPSHOT_ADDED, this::snapshotEvent);
			listenFor(TraceEvents.SNAPSHOT_DELETED, this::snapshotEvent);
			listenFor(TraceEvents.SNAPSHOT_CHANGED, this::snapshotEvent);
			listenForUntyped(DomainObjectEvent.RESTORED, e -> snapshotEvent());
		}

		void breakpointChanged(TraceBreakpointLocation tb) {
			refreshBreakpointHits();
			breakpointTimelinePlugin.refreshAllProviders(null);
		}

		void breakpointDeleted(TraceBreakpointLocation tb) {
			refreshBreakpointHits();
			breakpointTimelinePlugin.refreshAllProviders(null);
		}

		void snapshotEvent() {
			final long newMaxSnap =
				Objects.requireNonNullElse(currentTrace.getTimeManager().getMaxSnap(), 0)
						.longValue();

			if (newMaxSnap != curMaxSnap) {
				breakpointTimelinePanel.setEventsAndVisibleRange(breakpointHits, 0, newMaxSnap);
				curMaxSnap = newMaxSnap;
			}
		}
	}

	private class CloseAllZoomWindowsAction extends DockingAction {
		private final GIcon ICON =
			new GIcon("icon.debugger.breakpoint.timeline.close_all_zoom_windows");

		CloseAllZoomWindowsAction(ComponentProvider provider) {
			super("Close all zoom windows", provider.getOwner());
			setEnabled(true);
			setToolBarData(new ToolBarData(ICON, "1"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			breakpointTimelinePlugin.removeZoomProviders(currentTrace);
		}
	}

	private class SmallestCellSizeAction extends DockingAction {
		private final GIcon ICON = new GIcon("icon.debugger.breakpoint.timeline.zoom_out_max");

		SmallestCellSizeAction(ComponentProvider provider) {
			super("Set default cell size to the smallest", provider.getOwner());
			setEnabled(true);
			setToolBarData(new ToolBarData(ICON, "zoom"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			breakpointTimelinePanel.setMinimumDefaultCellSize();
		}
	}

	private class ToggleGridAction extends DockingAction {
		private final GIcon OUTLINE_ICON = new GIcon("icon.debugger.breakpoint.timeline.outline");
		private final GIcon NO_OUTLINE_ICON =
			new GIcon("icon.debugger.breakpoint.timeline.no_outline");
		private boolean grid = true;

		ToggleGridAction(ComponentProvider provider) {
			super("Toggle Grid Outline", provider.getOwner());
			setEnabled(true);
			setToolBarData(new ToolBarData(OUTLINE_ICON, "2"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			grid = !grid;
			getToolBarData().setIcon(grid ? OUTLINE_ICON : NO_OUTLINE_ICON);
			breakpointTimelinePanel.toggleGridOutline();
			breakpointTimelinePlugin.refreshAllProviders(BreakpointTimelineProvider.this);

		}
	}

	private class ToggleGridOrColumnAction extends DockingAction {
		private final GIcon GRID_ICON = new GIcon("icon.debugger.breakpoint.timeline.grid");
		private final GIcon SINGLE_COLUMN_ICON =
			new GIcon("icon.debugger.breakpoint.timeline.single_column");
		private boolean grid = true;

		ToggleGridOrColumnAction(ComponentProvider provider) {
			super("Toggle between grid and single column", provider.getOwner());
			setEnabled(true);
			setToolBarData(new ToolBarData(GRID_ICON, "2"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			grid = !grid;
			getToolBarData().setIcon(grid ? GRID_ICON : SINGLE_COLUMN_ICON);
			breakpointTimelinePanel.toggleGridOrColumn();
			breakpointTimelinePlugin.refreshAllProviders(BreakpointTimelineProvider.this);
		}
	}

	private class ZoomInAction extends DockingAction {
		private final GIcon ICON = new GIcon("icon.debugger.breakpoint.timeline.zoom_in");

		ZoomInAction(ComponentProvider provider) {
			super("Increase cell size", provider.getOwner());
			setEnabled(true);
			setToolBarData(new ToolBarData(ICON, "zoom"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			breakpointTimelinePanel.increaseDefaultCellSize();
		}
	}

	private class ZoomOutAction extends DockingAction {
		private final GIcon ICON = new GIcon("icon.debugger.breakpoint.timeline.zoom_out");

		ZoomOutAction(ComponentProvider provider) {
			super("Decrease cell size", provider.getOwner());
			setEnabled(true);
			setToolBarData(new ToolBarData(ICON, "zoom"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			breakpointTimelinePanel.decreaseDefaultCellSize();
		}
	}

	@Internal
	public static Iterator<? extends TraceObjectValue> getTraceObjectValuesWithPCsIntersectingRange(
			Trace trace, AddressRange range) {
		return trace.getObjectManager()
				.getRootSchema()
				.getContext()
				.getAllSchemas()
				.stream()
				.filter(s -> s.getInterfaces().contains(TraceStackFrame.class))
				.map(s -> s.checkAliasedAttribute(TraceStackFrame.KEY_PC))
				.flatMap(e -> trace.getObjectManager()
						.getValuesIntersecting(Lifespan.ALL, range, e)
						.stream())
				.sorted(Comparator.comparingLong(TraceObjectValue::getMinSnap))
				.iterator();
	}

	private final BreakpointTimelinePanel breakpointTimelinePanel;
	private final JPanel wrapperPanel;
	private final BreakpointTimelinePlugin breakpointTimelinePlugin;
	private final BreakpointTimeOverviewEventListener listener =
		new BreakpointTimeOverviewEventListener();
	private Trace currentTrace;
	private long curMaxSnap;
	private List<BreakpointHitEvent> breakpointHits;

	BreakpointTimelineProvider(BreakpointTimelinePlugin breakpointTimelinePlugin) {
		this(breakpointTimelinePlugin, false);
	}

	BreakpointTimelineProvider(BreakpointTimelinePlugin breakpointTimelinePlugin,
			boolean makeTransient) {
		super(breakpointTimelinePlugin.getTool(), "Breakpoint Timeline",
			breakpointTimelinePlugin.getName());
		this.breakpointTimelinePlugin = breakpointTimelinePlugin;
		wrapperPanel = new JPanel(new BorderLayout());
		breakpointTimelinePanel = new BreakpointTimelinePanel(this);
		breakpointTimelinePanel.setFocusable(true);
		wrapperPanel.add(breakpointTimelinePanel, BorderLayout.CENTER);
		breakpointHits = new ArrayList<>();

		if (makeTransient) {
			setTransient();
		}

		dockingTool.addComponentProvider(this, true);
		createActions();

	}

	BreakpointTimelineProvider(BreakpointTimelineProvider provider, String title, long start,
			long end) {
		this(provider.breakpointTimelinePlugin, true);
		currentTrace = provider.currentTrace;
		setTitle(title);
		breakpointHits = provider.breakpointHits;
		breakpointTimelinePanel.setEventsAndVisibleRange(breakpointHits, start, end);
	}

	private void createActions() {
		dockingTool.addLocalAction(this, new ToggleGridOrColumnAction(this));
		dockingTool.addLocalAction(this, new ToggleGridAction(this));
		dockingTool.addLocalAction(this, new ZoomInAction(this));
		dockingTool.addLocalAction(this, new ZoomOutAction(this));
		dockingTool.addLocalAction(this, new CloseAllZoomWindowsAction(this));
		dockingTool.addLocalAction(this, new SmallestCellSizeAction(this));
	}

	void createZoomProvider(String title, long start, long stop) {
		breakpointTimelinePlugin.createZoomProvider(title, start, stop);
	}

	private void findAndAddAllBreakpointHitsAtLocation(TraceBreakpointLocation breakpointLocation,
			AddressRange range, String kind) {
		for (final TraceBreakpointKind breakpointKind : TraceBreakpointKindSet.decode(kind,
			false)) {
			switch (breakpointKind) {
				case HW_EXECUTE, SW_EXECUTE -> findAndAddExecuteBreakpointHits(breakpointLocation,
					range);
				case READ, WRITE -> findAndAddMemoryBreakpointHits(breakpointLocation, range,
					breakpointKind);
			}
		}
	}

	private void findAndAddExecuteBreakpointHits(TraceBreakpointLocation breakpointLocation,
			AddressRange range) {
		final Iterator<? extends TraceObjectValue> intersecting =
			getTraceObjectValuesWithPCsIntersectingRange(currentTrace, range);

		while (intersecting.hasNext()) {
			final TraceObjectValue tov = intersecting.next();
			breakpointHits.add(new BreakpointHitEvent(tov.getMinSnap(),
				TraceBreakpointKind.SW_EXECUTE, breakpointLocation.getName(tov.getMinSnap())));
		}
	}

	private void findAndAddMemoryBreakpointHits(TraceBreakpointLocation breakpointLocation,
			AddressRange range, TraceBreakpointKind kind) {
		for (final TraceReference reference : currentTrace.getReferenceManager()
				.getReferencesToRange(Lifespan.ALL, range)) {

			if ((reference.getReferenceType() == RefType.READ) &&
				(kind == TraceBreakpointKind.READ)) {
				breakpointHits.add(
					new BreakpointHitEvent(reference.getStartSnap(), TraceBreakpointKind.READ,
						breakpointLocation.getName(reference.getStartSnap())));
			}

			if ((reference.getReferenceType() == RefType.WRITE) &&
				(kind == TraceBreakpointKind.WRITE)) {
				breakpointHits.add(
					new BreakpointHitEvent(reference.getStartSnap(), TraceBreakpointKind.WRITE,
						breakpointLocation.getName(reference.getStartSnap())));
			}
		}
	}

	@Override
	public JComponent getComponent() {
		return wrapperPanel;
	}

	void refresh() {
		breakpointTimelinePanel.refresh();
	}

	private void refreshBreakpointHits() {
		breakpointHits.clear();

		if (currentTrace == null) {
			return;
		}

		// LATER: Check if breakpoint is enabled after GP-6441 is done
		for (final TraceBreakpointLocation breakpointLocation : currentTrace.getBreakpointManager()
				.getAllBreakpointLocations()) {

			for (final TraceObjectValue traceVal : breakpointLocation.getObject()
					.getValues(Lifespan.ALL, TraceBreakpointLocation.KEY_RANGE)) {
				if (!(traceVal.getValue() instanceof final AddressRange range)) {
					continue;
				}
				for (final TraceObjectValue specValue : breakpointLocation.getSpecification()
						.getObject()
						.getValues(Lifespan.ALL, TraceBreakpointSpec.KEY_KINDS)) {

					if (!(specValue.getValue() instanceof final String kind)) {
						continue;
					}

					findAndAddAllBreakpointHitsAtLocation(breakpointLocation, range, kind);
				}
			}
		}
	}

	void setTrace(Trace trace) {
		if (currentTrace != null) {
			currentTrace.removeListener(listener);
		}
		currentTrace = trace;
		curMaxSnap = 0;
		refreshBreakpointHits();

		if (currentTrace != null) {
			curMaxSnap = Objects.requireNonNullElse(currentTrace.getTimeManager().getMaxSnap(), 0)
					.longValue();
			breakpointTimelinePanel.setEventsAndVisibleRange(breakpointHits, 0, curMaxSnap);
			currentTrace.addListener(listener);
		}
		else {
			breakpointTimelinePanel.setEventsAndVisibleRange(null, 0, 0);
		}
	}
}
