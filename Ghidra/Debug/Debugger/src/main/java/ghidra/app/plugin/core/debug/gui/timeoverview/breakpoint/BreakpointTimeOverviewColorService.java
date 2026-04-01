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
package ghidra.app.plugin.core.debug.gui.timeoverview.breakpoint;

import java.awt.Color;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.math.BigInteger;
import java.util.*;

import javax.swing.SwingUtilities;

import docking.DialogComponentProvider;
import docking.action.DockingActionIf;
import docking.action.builder.ActionBuilder;
import generic.ULongSpan;
import generic.theme.GThemeDefaults.Colors;
import ghidra.app.plugin.core.debug.gui.timeoverview.*;
import ghidra.app.plugin.core.overview.OverviewColorLegendDialog;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.symbol.RefType;
import ghidra.trace.model.*;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.symbol.TraceReference;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.util.TraceEvents;
import ghidra.util.ColorUtils;
import ghidra.util.HelpLocation;

record BreakpointEvent(long snap, CellType breakType) {}

public class BreakpointTimeOverviewColorService implements TimeOverviewColorService {
	private class BreakpointTimeOverviewEventListener extends TraceDomainObjectListener {

		public BreakpointTimeOverviewEventListener() {
			listenFor(TraceEvents.BREAKPOINT_ADDED, this::breakpointAdded);
			listenFor(TraceEvents.BREAKPOINT_CHANGED, this::breakpointChanged);
			listenFor(TraceEvents.BREAKPOINT_DELETED, this::breakpointDeleted);
			listenFor(TraceEvents.BREAKPOINT_LIFESPAN_CHANGED, this::breakpointLifespanChanged);
		}

		void breakpointAdded(TraceBreakpointLocation tb) {
			// Empty because all new breakpoints fire a breakpoint change
			// event
		}

		void breakpointChanged(TraceBreakpointLocation tb) {
			SwingUtilities.invokeLater(() -> {
				calculateBreakpointHits();
				calculateHelperMaps();
			});
		}

		void breakpointDeleted(TraceBreakpointLocation tb) {
			SwingUtilities.invokeLater(() -> {
				calculateBreakpointHits();
				calculateHelperMaps();
			});
		}

		void breakpointLifespanChanged(TraceBreakpointLocation tb) {
			SwingUtilities.invokeLater(() -> {
				calculateBreakpointHits();
				calculateHelperMaps();
			});
		}

	}

	private static String OPTIONS_NAME = "Breakpoint Hit Timeline";

	private PluginTool tool;

	Trace currentTrace;
	TimeOverviewColorComponent overviewComponent;
	DialogComponentProvider legendDialog;
	BreakTypeOverviewLegendPanel legendPanel;
	TimeOverviewColorPlugin plugin;

	private final BreakpointTimeOverviewEventListener eventListener =
		new BreakpointTimeOverviewEventListener();

	private final Map<CellType, Color> colorMap = new HashMap<>();
	private final Map<Integer, Long> indexToSnap = new HashMap<>();
	private final Map<Long, Color> snapToColor = new HashMap<>();
	private final Map<Long, String> snapToTooltip = new HashMap<>();
	private final Map<Long, ULongSpan> snapToRange = new HashMap<>();

	List<BreakpointEvent> snapsWithBreakpointsHit = new ArrayList<>();

	Lifespan bounds;
	private DebuggerTraceManagerService debuggerTraceManagerService;

	protected void calculateBreakpointHits() {
		snapsWithBreakpointsHit.clear();

		// LATER: Check if breakpoint is enabled after GP-6441 is done
		for (final TraceBreakpointLocation breakpointLocation : getTrace().getBreakpointManager()
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

	protected void calculateHelperMaps() {
		indexToSnap.clear();
		snapToColor.clear();
		if (bounds == null) {
			return;
		}
		final long splits = overviewComponent.getOverviewPixelCount();
		final long snapSpanPerCell = Math.max((bounds.lmax() - bounds.lmin()) / splits, 1);

		int cellIndex = 0;
		for (long i = 0; i < bounds.lmax(); i += snapSpanPerCell) {
			boolean hasBreakpointHit = false;
			Color cellColor = Colors.BACKGROUND;

			for (final BreakpointEvent event : snapsWithBreakpointsHit) {
				if ((i <= event.snap()) && (event.snap() <= (i + snapSpanPerCell))) {
					hasBreakpointHit = true;
					indexToSnap.put(cellIndex, event.snap());
					snapToTooltip.put(event.snap(), """
							Snapshot %d
							Break type %s""".formatted(event.snap(), event.breakType()));
					snapToRange.put(event.snap(), ULongSpan.span(i, i + snapSpanPerCell));

					cellColor =
						ColorUtils.addColors(cellColor, event.breakType().getDefaultColor());
				}
			}

			if (!hasBreakpointHit) {
				// Just use the first snap of this span
				indexToSnap.put(cellIndex, i);
				snapToRange.put(i, ULongSpan.span(i, i + snapSpanPerCell));
				snapToTooltip.put(i, "Snapshot %d".formatted(i));
			}

			snapToColor.put(indexToSnap.get(cellIndex), cellColor);

			cellIndex++;
		}

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
		final Collection<? extends TraceObjectValue> intersecting = currentTrace.getObjectManager()
				.getValuesIntersecting(Lifespan.ALL, range, TraceStackFrame.KEY_PC);
		for (final TraceObjectValue tov : intersecting) {
			snapsWithBreakpointsHit
					.add(new BreakpointEvent(tov.getMinSnap(), CellType.INSTRUCTION_EXECUTED));
		}
	}

	private void findAndAddMemoryBreakpointHits(TraceBreakpointLocation breakpointLocation,
			AddressRange range, TraceBreakpointKind kind) {
		for (final TraceReference reference : currentTrace.getReferenceManager()
				.getReferencesToRange(Lifespan.ALL, range)) {

			if ((reference.getReferenceType() == RefType.READ) &&
				(kind == TraceBreakpointKind.READ)) {
				snapsWithBreakpointsHit
						.add(new BreakpointEvent(reference.getStartSnap(), CellType.MEMORY_READ));
			}

			if ((reference.getReferenceType() == RefType.WRITE) &&
				(kind == TraceBreakpointKind.WRITE)) {
				snapsWithBreakpointsHit.add(
					new BreakpointEvent(reference.getStartSnap(), CellType.MEMORY_WRITTEN));
			}
		}
	}

	@Override
	public List<DockingActionIf> getActions() {
		final List<DockingActionIf> actions = new ArrayList<>();
		actions.add(new ActionBuilder("Show Legend", getName()).popupMenuPath("Show Legend")
				.description("Show types and associated colors")
				.helpLocation(getHelpLocation())
				.enabledWhen(c -> c.getContextObject() == overviewComponent)
				.onAction(c -> tool.showDialog(getLegendDialog()))
				.build());

		return actions;
	}

	@Override
	public Lifespan getBounds() {
		return bounds;
	}

	/**
	 * Returns the color associated with the given {@link CellType}
	 *
	 * @param breakType the span type for which to get a color.
	 * @return the color associated with the given {@link CellType}
	 */
	public Color getColor(CellType breakType) {
		final Color color = colorMap.get(breakType);
		if (color == null) {
			colorMap.put(breakType, breakType.getDefaultColor());
		}
		return color;
	}

	@Override
	public Color getColor(Long snap) {
		final Color c = Colors.BACKGROUND;

		if (snap != null) {
			final ULongSpan range = snapToRange.get(snap);
			final long currentSnap = debuggerTraceManagerService.getCurrentSnap();
			if ((range != null) && (currentSnap > range.min()) && (currentSnap < range.max())) {
				return Color.GREEN;
			}
			return snapToColor.get(snap);
		}
		return c;
	}

	@Override
	public HelpLocation getHelpLocation() {
		return null;
	}

	private DialogComponentProvider getLegendDialog() {
		if (legendDialog == null) {
			legendPanel = new BreakTypeOverviewLegendPanel(this);

			legendDialog =
				new OverviewColorLegendDialog("Overview Legend", legendPanel, getHelpLocation());
		}
		return legendDialog;
	}

	@Override
	public String getName() {
		return OPTIONS_NAME;
	}

	@Override
	public Long getSnap(int pixelIndex) {
		final BigInteger bigHeight = BigInteger.valueOf(overviewComponent.getOverviewPixelCount());
		final BigInteger bigPixelIndex = BigInteger.valueOf(pixelIndex);

		final BigInteger span = BigInteger.valueOf(indexToSnap.size());
		final BigInteger offset = span.multiply(bigPixelIndex).divide(bigHeight);
		return indexToSnap.get(offset.intValue());
	}

	@Override
	public String getToolTipText(Long snap) {
		return snapToTooltip.getOrDefault(snap, "Snapshot %d".formatted(snap));
	}

	@Override
	public Trace getTrace() {
		return currentTrace;
	}

	@Override
	public void initialize(PluginTool pluginTool) {
		tool = pluginTool;
		debuggerTraceManagerService = tool.getService(DebuggerTraceManagerService.class);
	}

	@Override
	public void setBounds(Lifespan bounds) {
		if (currentTrace != null) {
			this.bounds = Lifespan.span(0, getTrace().getTimeManager().getMaxSnap());
		}
	}

	public void setColor(CellType type, Color newColor) {
		final ToolOptions options = tool.getOptions(OPTIONS_NAME);
		options.setColor(type.getDescription(), newColor);
	}

	@Override
	public void setIndices(TreeSet<Long> set) {
		// Empty because we do not change indices once a trace is set
	}

	@Override
	public void setOverviewComponent(TimeOverviewColorComponent component) {
		overviewComponent = component;
		overviewComponent.addComponentListener(new ComponentAdapter() {

			@Override
			public void componentResized(ComponentEvent e) {
				SwingUtilities.invokeLater(() -> calculateHelperMaps());
			}
		});
	}

	@Override
	public void setPlugin(TimeOverviewColorPlugin plugin) {
		this.plugin = plugin;
	}

	@Override
	public void setTrace(Trace trace) {
		if ((trace != null) && (trace != currentTrace)) {
			if (currentTrace != null) {
				currentTrace.removeListener(eventListener);
			}
			currentTrace = trace;
			currentTrace.addListener(eventListener);
			SwingUtilities.invokeLater(this::calculateHelperMaps);
			bounds = Lifespan.span(0, getTrace().getTimeManager().getMaxSnap());
		}
	}
}