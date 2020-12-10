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
package ghidra.app.plugin.core.debug.gui.timeline;

import java.awt.*;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;

import com.google.common.collect.Range;

import docking.widgets.*;
import docking.widgets.RangeCursorPanel.Direction;
import docking.widgets.table.RowObjectTableModel;
import docking.widgets.timeline.TimelinePanel;
import docking.widgets.timeline.TimelineViewRangeListener;
import ghidra.util.datastruct.ListenerSet;

public class DebuggerTimelinePanel extends JScrollPane {
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

	protected class ObjectTimelinePanel extends TimelinePanel<TimelineRow, Long> {
		private DebuggerTimelinePanel panel;

		public ObjectTimelinePanel(DebuggerTimelinePanel panel,
				RowObjectTableModel<TimelineRow> model) {
			super(model, TimelineRow::getLifespan);
			this.panel = panel;
		}

		@Override
		protected void selectionChanged(ListSelectionEvent e) {
			super.selectionChanged(e);
			List<TimelineRow> items = rows.items();
			int min = selectionModel.getMinSelectionIndex();
			if (items != null && min >= 0) {
				TimelineRow row = items.get(min);
				Component component = getComponent(row);
				Point loc = component.getLocation();
				JViewport vp = panel.getViewport();
				vp.setViewPosition(new Point(loc.x, vp.getView().getY()));
			}
		}
	}

	protected class ObjectRangeCursorPanel extends RangeCursorPanel {
		public ObjectRangeCursorPanel(Direction direction) {
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

	protected final ObjectTimelinePanel timeline;
	protected final RangeCursorPanel topCursor = new ObjectRangeCursorPanel(Direction.SOUTH) {
		Dimension preferredSize = new Dimension(super.getPreferredSize());

		@Override
		public Dimension getPreferredSize() {
			preferredSize.width = timeline.getPreferredSize().width;
			return preferredSize;
		}
	};
	protected final ListenerSet<VetoableSnapRequestListener> listeners =
		new ListenerSet<>(VetoableSnapRequestListener.class);
	protected final RangeCursorValueListener positionListener = this::cursorPositionChanged;
	protected final TimelineViewRangeListener viewRangeListener = this::viewRangeChanged;

	protected ListSelectionModel selectionModel;

	public DebuggerTimelinePanel(RowObjectTableModel<TimelineRow> model) {
		setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);

		timeline = new ObjectTimelinePanel(this, model);
		timeline.setCompressed(false);
		setViewportView(timeline);
		setColumnHeaderView(topCursor);

		topCursor.addValueListener(positionListener);
		timeline.addViewRangeListener(viewRangeListener);
	}

	public void addSnapRequestedListener(VetoableSnapRequestListener listener) {
		listeners.add(listener);
	}

	private void cursorPositionChanged(double position, EventTrigger trigger) {
//		try {
//			listeners.fire.snapRequested(Math.round(position), trigger);
//		}
//		catch (SnapRequestVetoedException e) {
//			position = e.getNewSnap();
//		}
	}

	private void viewRangeChanged(Range<Double> range) {
		topCursor.setRange(range);
	}

	public void setSelectionModel(ListSelectionModel selectionModel) {
		timeline.setSelectionModel(selectionModel);
	}

	public void setSnap(long snap) {
		topCursor.requestValue(snap);
	}

	public void setMaxSnapAtLeast(Long maxSnapAtLeast) {
		if (maxSnapAtLeast != null) {
			timeline.setMaxAtLeast(maxSnapAtLeast);
		}
	}
}
