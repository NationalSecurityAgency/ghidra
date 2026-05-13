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

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

import javax.swing.JPanel;

import generic.theme.GColor;
import generic.theme.GThemeDefaults.Colors;
import ghidra.app.plugin.core.debug.gui.breakpoint.timeline.BreakpointTimelineProvider.BreakpointHitEvent;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.util.ColorUtils;
import ghidra.util.Swing;

class BreakpointTimelinePanel extends JPanel {
	private static class CachedIndex {
		private final long startSnap;
		private final long stopSnap;
		private final List<BreakpointHitEvent> breakpointEvents;
		Rectangle rect;
		long index;

		CachedIndex(long startSnap, long stopSnap, Rectangle rect, long index) {
			this.startSnap = startSnap;
			this.stopSnap = stopSnap;
			this.rect = rect;
			this.index = index;
			breakpointEvents = new ArrayList<>();
		}

		void addEvent(BreakpointHitEvent event) {
			breakpointEvents.add(event);
		}

		Color getColor() {
			Color retColor = null;
			final List<TraceBreakpointKind> uniqueBreakTypes =
				breakpointEvents.stream().map(BreakpointHitEvent::breakType).distinct().toList();
			final double blendRatio = 1.0d / uniqueBreakTypes.size();

			for (final TraceBreakpointKind bt : uniqueBreakTypes) {
				if (retColor == null) {
					retColor = BreakpointTimelinePanel.BREAKTYPE_TO_COLOR.get(bt);
					continue;
				}
				retColor = ColorUtils.blend(BreakpointTimelinePanel.BREAKTYPE_TO_COLOR.get(bt),
					retColor, blendRatio);
			}

			return (retColor == null) ? BreakpointTimelinePanel.BG_COLOR : retColor;
		}

		long getIndex() {
			return index;
		}

		BreakpointHitEvent getMainEvent() {
			if (breakpointEvents.isEmpty()) {
				return null;
			}
			return breakpointEvents.getFirst();
		}

		long getMainSnap() {
			final BreakpointHitEvent mainEvent = getMainEvent();
			return (mainEvent != null) ? mainEvent.snap() : startSnap;
		}

		Rectangle getRect() {
			return rect;
		}

		long getStartSnap() {
			return startSnap;
		}

		long getStopSnap() {
			return stopSnap;
		}
	}

	private static boolean singleColumn = false;
	private static boolean showGridOutline = true;

	private static GColor BG_COLOR = Colors.BACKGROUND;
	private static GColor GRID_COLOR = Colors.FOREGROUND_DISABLED;
	private static GColor SELECTION_COLOR =
		new GColor("color.debugger.plugin.breakpoint.timeline.selection");
	private static GColor HOVER_COLOR =
		new GColor("color.debugger.plugin.breakpoint.timeline.hover");
	private static GColor CURRENT_SNAP_COLOR =
		new GColor("color.debugger.plugin.breakpoint.timeline.current");
	private static GColor INSTRUCTION_HIT_COLOR =
		new GColor("color.debugger.plugin.breakpoint.timeline.type.instructions");
	private static GColor MEMORY_READ_COLOR =
		new GColor("color.debugger.plugin.breakpoint.timeline.type.read.memory");
	private static GColor MEMORY_WRITE_COLOR =
		new GColor("color.debugger.plugin.breakpoint.timeline.type.write.memory");
	private static Map<TraceBreakpointKind, GColor> BREAKTYPE_TO_COLOR = Map.ofEntries(
		Map.entry(TraceBreakpointKind.HW_EXECUTE, BreakpointTimelinePanel.INSTRUCTION_HIT_COLOR),
		Map.entry(TraceBreakpointKind.SW_EXECUTE, BreakpointTimelinePanel.INSTRUCTION_HIT_COLOR),
		Map.entry(TraceBreakpointKind.READ, BreakpointTimelinePanel.MEMORY_READ_COLOR),
		Map.entry(TraceBreakpointKind.WRITE, BreakpointTimelinePanel.MEMORY_WRITE_COLOR));

	private long defaultCellSize = 10;

	private List<BreakpointHitEvent> events;
	private final BreakpointTimelineProvider provider;

	private long cellWidth = defaultCellSize;
	private long cellHeight = defaultCellSize;
	private long visibleStart;

	private long visibleEnd;
	private Point dragStart;
	private Point dragEnd;
	private Point mousePos;

	private long gridWidth;
	private long gridHeight;

	private CachedIndex lastHighlightedIndex;
	private CachedIndex startDragIndex;
	private CachedIndex endDragIndex;

	private final Map<Long, CachedIndex> cells = new HashMap<>();

	BreakpointTimelinePanel(BreakpointTimelineProvider provider) {
		events = null;
		this.provider = provider;
		setup();
	}

	private void calculateGridAndBuildCache() {
		Swing.runIfSwingOrRunLater(this::doCalculateGridAndBuildCache);
	}

	private void click(Point p) {
		final Optional<BreakpointTimelinePanel.CachedIndex> first =
			cells.values().stream().filter(s -> s.getRect().contains(p)).findFirst();
		if (first.isPresent()) {
			getTraceManagerService().activateSnap(first.get().getMainSnap());
		}
	}

	void decreaseDefaultCellSize() {
		defaultCellSize = Math.max(cellHeight - 1, 1);
		calculateGridAndBuildCache();
	}

	private void doCalculateGridAndBuildCache() {
		if ((visibleStart == 0) && (visibleEnd == 0)) {
			cells.clear();
			repaint();
			return;
		}
		final int width = getWidth();
		final int height = getHeight();

		if ((width <= 0) && (height <= 0)) {
			return;
		}

		if (!BreakpointTimelinePanel.singleColumn) {
			final long numCells = visibleEnd - visibleStart;

			double xSideLength;
			double ySideLength;

			final double xPixelsPerCell = Math.ceil(Math.sqrt((numCells * width) / height));
			if ((Math.floor((xPixelsPerCell * height) / width) * xPixelsPerCell) < numCells) {
				xSideLength = (height / Math.ceil((height * xPixelsPerCell) / width));
			}
			else {
				xSideLength = width / xPixelsPerCell;
			}

			final double yPixelsPerCell = Math.ceil(Math.sqrt((numCells * height) / width));
			if ((Math.floor((yPixelsPerCell * width) / height) * yPixelsPerCell) < numCells) {
				ySideLength = (width / Math.ceil((width * yPixelsPerCell) / height));
			}
			else {
				ySideLength = height / yPixelsPerCell;
			}

			final long potentialSideLength = (long) Math.max(xSideLength, ySideLength);

			cellWidth = Math.max(defaultCellSize, potentialSideLength);
			cellHeight = cellWidth;

			gridWidth = Math.max(width / cellWidth, 1);
		}
		else {
			final long numCells = visibleEnd - visibleStart;
			final long cellHeightOption = height / numCells;
			cellHeight = Math.max(defaultCellSize, cellHeightOption);
			cellWidth = width;
			gridWidth = 1;
		}
		gridHeight = Math.max(height / cellHeight, 1);

		cells.clear();

		final long totalCells = gridWidth * gridHeight;
		final long range = visibleEnd - visibleStart;
		final long span = Math.max(((range + totalCells) - 1) / totalCells, 1);
		long index = 0;

		for (long i = 0; i < range; i += span) {
			final long row = index / gridWidth;
			final long col = index % gridWidth;
			final long x = col * cellWidth;
			final long y = row * cellHeight;
			final long startSnap = i + visibleStart;
			final long stopSnap = i + visibleStart + Math.min(span, range - i);
			cells.put(index, new CachedIndex(startSnap, stopSnap,
				new Rectangle((int) x, (int) y, (int) cellWidth, (int) cellHeight), index));
			index++;
		}

		setPreferredSize(
			new Dimension((int) (gridWidth * cellWidth), (int) (gridHeight * cellHeight)));

		for (final BreakpointHitEvent event : events) {
			if ((event.snap() >= visibleStart) && (event.snap() < visibleEnd)) {
				final long cellIndex = (event.snap() - visibleStart) / span;
				final CachedIndex curSpan = cells.get(cellIndex);
				curSpan.addEvent(event);
			}
		}

		repaint();
	}

	@Override
	public String getToolTipText(MouseEvent event) {
		final Optional<BreakpointTimelinePanel.CachedIndex> first =
			cells.values().stream().filter(s -> s.getRect().contains(event.getPoint())).findFirst();
		if (first.isPresent()) {
			final CachedIndex index = first.get();
			final BreakpointHitEvent mainEvent = index.getMainEvent();
			if (mainEvent != null) {
				return """
						Snapshots %d - %d
						Jumps to snapshot %d
						Event type %s
						From %s
						""".formatted(index.getStartSnap(), index.getStopSnap() - 1,
					index.getMainSnap(), mainEvent.breakType(), mainEvent.breakpointName());
			}
			return """
					Snapshots %d - %d
					Jumps to snapshot %d
					""".formatted(index.getStartSnap(), index.getStopSnap() - 1,
				index.getMainSnap());
		}
		return "";
	}

	private DebuggerTraceManagerService getTraceManagerService() {
		return provider.getTool().getService(DebuggerTraceManagerService.class);
	}

	void increaseDefaultCellSize() {
		defaultCellSize = cellHeight + 1;
		calculateGridAndBuildCache();
	}

	@Override
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);

		if ((visibleStart == 0) && (visibleEnd == 0)) {
			return;
		}

		if ((gridWidth == 0) || (gridHeight == 0)) {
			calculateGridAndBuildCache();
		}

		final Graphics2D g2d = (Graphics2D) g;

		for (final Long cellIndex : cells.keySet()) {
			final CachedIndex curSpan = cells.get(cellIndex);
			if ((startDragIndex != null) && (endDragIndex != null) &&
				(cellIndex >= startDragIndex.getIndex()) &&
				(cellIndex <= endDragIndex.getIndex())) {
				g2d.setColor(BreakpointTimelinePanel.SELECTION_COLOR);
			}
			else if ((getTraceManagerService().getCurrentSnap() >= curSpan.getStartSnap()) &&
				(getTraceManagerService().getCurrentSnap() < curSpan.getStopSnap())) {
				g2d.setColor(BreakpointTimelinePanel.CURRENT_SNAP_COLOR);
			}
			else if ((mousePos != null) && curSpan.getRect().contains(mousePos)) {
				g2d.setColor(BreakpointTimelinePanel.HOVER_COLOR);
			}
			else {
				g2d.setColor(curSpan.getColor());
			}
			g2d.fillRect(curSpan.getRect().x, curSpan.getRect().y, curSpan.getRect().width,
				curSpan.getRect().height);
			if (BreakpointTimelinePanel.showGridOutline) {
				g2d.setColor(BreakpointTimelinePanel.GRID_COLOR);
				g2d.drawRect(curSpan.getRect().x, curSpan.getRect().y, curSpan.getRect().width,
					curSpan.getRect().height);
			}
		}
	}

	void refresh() {
		calculateGridAndBuildCache();
	}

	void setEventsAndVisibleRange(List<BreakpointHitEvent> events, long start, long stop) {
		this.events = events;
		visibleStart = start;
		visibleEnd = stop;
		calculateGridAndBuildCache();
	}

	void setMinimumDefaultCellSize() {
		defaultCellSize = 1;
		calculateGridAndBuildCache();
	}

	private void setup() {
		setToolTipText("");
		setBackground(BreakpointTimelinePanel.BG_COLOR);

		addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				calculateGridAndBuildCache();
			}
		});

		addMouseListener(new MouseAdapter() {
			@Override
			public void mouseExited(MouseEvent e) {
				mousePos = null;
				repaint();
			}

			@Override
			public void mousePressed(MouseEvent e) {
				dragStart = e.getPoint();
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				if (dragEnd != null) {
					zoom();
				}
				else {
					click(dragStart);
				}
				dragStart = null;
				dragEnd = null;
				startDragIndex = null;
				endDragIndex = null;
				repaint();
			}
		});

		addMouseWheelListener(new MouseAdapter() {

			@Override
			public void mouseWheelMoved(MouseWheelEvent e) {
				final int rotation = e.getWheelRotation();
				if (rotation > 0) {
					getTraceManagerService()
							.activateSnap(getTraceManagerService().getCurrentSnap() + 1);
				}
				else {
					getTraceManagerService()
							.activateSnap(getTraceManagerService().getCurrentSnap() - 1);

				}
				repaint();
			}
		});

		addMouseMotionListener(new MouseAdapter() {
			@Override
			public void mouseDragged(MouseEvent e) {
				dragEnd = e.getPoint();
				final Optional<BreakpointTimelinePanel.CachedIndex> start = cells.values()
						.stream()
						.filter(s -> s.getRect().contains(dragStart))
						.findFirst();
				if (start.isPresent()) {
					final Optional<BreakpointTimelinePanel.CachedIndex> end = cells.values()
							.stream()
							.filter(s -> s.getRect().contains(dragEnd))
							.findFirst();
					if (end.isPresent()) {
						if (start.get().getIndex() < end.get().getIndex()) {
							startDragIndex = start.get();
							endDragIndex = end.get();
						}
						else {
							startDragIndex = end.get();
							endDragIndex = start.get();
						}
					}
				}
				repaint();
			}

			@Override
			public void mouseMoved(MouseEvent e) {
				mousePos = e.getPoint();
				final Optional<BreakpointTimelinePanel.CachedIndex> indexSpan =
					cells.values().stream().filter(s -> s.getRect().contains(mousePos)).findFirst();
				if (indexSpan.isPresent() && (lastHighlightedIndex != indexSpan.get())) {
					lastHighlightedIndex = indexSpan.get();
					repaint();
				}
			}
		});
	}

	void toggleGridOrColumn() {
		BreakpointTimelinePanel.singleColumn = !BreakpointTimelinePanel.singleColumn;
		calculateGridAndBuildCache();
	}

	void toggleGridOutline() {
		BreakpointTimelinePanel.showGridOutline = !BreakpointTimelinePanel.showGridOutline;
		repaint();
	}

	private void zoom() {
		final Optional<BreakpointTimelinePanel.CachedIndex> start =
			cells.values().stream().filter(s -> s.getRect().contains(dragStart)).findFirst();
		if (start.isPresent()) {
			long startSnap = start.get().getStartSnap();

			final Optional<BreakpointTimelinePanel.CachedIndex> stop =
				cells.values().stream().filter(s -> s.getRect().contains(dragEnd)).findFirst();
			if (stop.isPresent()) {
				long endSnap = stop.get().getStopSnap();

				if (startSnap > endSnap) {
					final long temp = startSnap;
					startSnap = endSnap;
					endSnap = temp;
				}

				final String zoomName = "Timeline Zoom: %d - %d".formatted(startSnap, endSnap - 1);
				provider.createZoomProvider(zoomName, startSnap, endSnap);
			}
		}
	}
}
