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
package ghidra.app.plugin.core.debug.gui.thread;

import java.awt.Dimension;
import java.awt.Rectangle;
import java.util.List;

import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;

import com.google.common.collect.Range;

import docking.widgets.*;
import docking.widgets.RangeCursorPanel.Direction;
import docking.widgets.table.RowObjectTableModel;
import docking.widgets.timeline.TimelineListener;
import docking.widgets.timeline.TimelinePanel;
import ghidra.app.services.DebuggerModelService;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.datastruct.ListenerSet;

public class DebuggerThreadsTimelinePanel extends JScrollPane {
	static class SnapRequestVetoedException extends Exception {
		private final long requestedSnap;
		private final long newSnap;

		public SnapRequestVetoedException(long requestedSnap, long newSnap) {
			this.requestedSnap = requestedSnap;
			this.newSnap = newSnap;
		}

		public long getRequestedSnap() {
			return requestedSnap;
		}

		public long getNewSnap() {
			return newSnap;
		}
	}

	public interface VetoableSnapRequestListener {
		void snapRequested(long snap, EventTrigger trigger) throws SnapRequestVetoedException;
	}

	protected class ThreadTimelinePanel extends TimelinePanel<ThreadRow, Long> {
		protected final RowObjectTableModel<ThreadRow> model;

		public ThreadTimelinePanel(RowObjectTableModel<ThreadRow> model) {
			super(model, ThreadRow::getLifespan);
			this.model = model;
		}
	}

	protected class ThreadRangeCursorPanel extends RangeCursorPanel {
		public ThreadRangeCursorPanel(Direction direction) {
			super(direction);
		}

		@Override
		protected double adjustRequestedValue(double requested) {
			double rounded = Math.round(requested);
			// TODO: Also remove 1-snap view buffer?
			// Until I figure out the event processing order, leaving the buffer
			// prevents some stepping glitches.
			if (range.hasLowerBound() && rounded < range.lowerEndpoint() /*+1*/) {
				return range.lowerEndpoint(); // +1
			}
			if (range.hasUpperBound() && rounded > range.upperEndpoint() /*-1*/) {
				return range.upperEndpoint(); // -1
			}
			return rounded;
		}
	}

	protected final ThreadTimelinePanel timeline;
	protected final RangeCursorPanel topCursor = new ThreadRangeCursorPanel(Direction.SOUTH) {
		Dimension preferredSize = new Dimension(super.getPreferredSize());

		@Override
		public Dimension getPreferredSize() {
			preferredSize.width = timeline.getPreferredSize().width;
			return preferredSize;
		}
	};
	protected final ListenerSet<VetoableSnapRequestListener> listeners =
		new ListenerSet<>(VetoableSnapRequestListener.class);
	protected final RangeCursorValueListener valueListener = this::cursorValueChanged;
	protected final TimelineListener timelineListener = new TimelineListener() {
		@Override
		public void viewRangeChanged(Range<Double> range) {
			timelineViewRangeChanged(range);
		}
	};
	private DebuggerModelService modelService;
	private RowObjectTableModel<ThreadRow> model;

	public DebuggerThreadsTimelinePanel(RowObjectTableModel<ThreadRow> model) {
		this.model = model;
		setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);

		timeline = new ThreadTimelinePanel(model);
		setViewportView(timeline);
		setColumnHeaderView(topCursor);

		topCursor.addValueListener(valueListener);
		timeline.addTimelineListener(timelineListener);
	}

	public void addSnapRequestedListener(VetoableSnapRequestListener listener) {
		listeners.add(listener);
	}

	private void cursorValueChanged(double value, EventTrigger trigger) {
		try {
			listeners.fire.snapRequested(Math.round(value), trigger);
		}
		catch (SnapRequestVetoedException e) {
			value = e.getNewSnap();
		}
	}

	private void timelineViewRangeChanged(Range<Double> range) {
		topCursor.setRange(range);
	}

	public void setSelectionModel(ListSelectionModel selectionModel) {
		timeline.setSelectionModel(selectionModel);
	}

	public void setSnap(long snap) {
		topCursor.requestValue(snap);
	}

	public long getSnap() {
		// TODO: If there are enough snaps, we may not have the required precision
		// Consider BigDecimal in cursor? Eww.
		return (long) topCursor.getValue();
	}

	public void setMaxSnapAtLeast(long maxSnapAtLeast) {
		timeline.setMaxAtLeast(maxSnapAtLeast);
	}

	public long getMaxSnapAtLeast() {
		return (long) timeline.getMaxAtLeast();
	}

	public ThreadRow findRow(TraceThread thread) {
		RowObjectTableModel<ThreadRow> model = timeline.getTableModel();
		List<ThreadRow> data = model.getModelData();
		for (ThreadRow row : data) {
			if (row.getThread() == thread) {
				return row;
			}
		}
		return null;
	}

	public Rectangle getCellBounds(TraceThread thread) {
		ThreadRow row = findRow(thread);
		if (row == null) {
			return null;
		}
		return timeline.getCellBounds(row);
	}

	public void addTimelineListener(TimelineListener listener) {
		timeline.addTimelineListener(listener);
	}
}
