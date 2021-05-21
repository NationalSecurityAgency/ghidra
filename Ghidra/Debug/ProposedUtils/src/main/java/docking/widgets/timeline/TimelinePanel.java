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
package docking.widgets.timeline;

import java.awt.*;
import java.awt.event.*;
import java.awt.event.FocusEvent.Cause;
import java.util.*;
import java.util.List;
import java.util.Map.Entry;
import java.util.function.Function;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.*;

import com.google.common.collect.*;

import docking.widgets.table.RowObjectTableModel;
import ghidra.util.Swing;
import ghidra.util.UIManagerWrapper;
import ghidra.util.datastruct.ListenerSet;

public class TimelinePanel<T, N extends Number & Comparable<N>> extends JPanel {
	public static final int INSET_WIDTH = 2;
	public static final int SLACK = 1;

	public static <N extends Number & Comparable<N>, M extends Number & Comparable<M>> Range<M> mapRangeEndpoints(
			Range<N> range, Function<N, M> func) {
		// Weeeeeeee!!!!!!!
		if (range.hasLowerBound()) {
			if (range.hasUpperBound()) {
				if (range.lowerBoundType() == BoundType.CLOSED) {
					if (range.upperBoundType() == BoundType.CLOSED) {
						return Range.closed(func.apply(range.lowerEndpoint()),
							func.apply(range.upperEndpoint()));
					}
					return Range.closedOpen(func.apply(range.lowerEndpoint()),
						func.apply(range.upperEndpoint()));
				}
				if (range.upperBoundType() == BoundType.CLOSED) {
					return Range.openClosed(func.apply(range.lowerEndpoint()),
						func.apply(range.upperEndpoint()));
				}
				return Range.open(func.apply(range.lowerEndpoint()),
					func.apply(range.upperEndpoint()));
			}
			if (range.lowerBoundType() == BoundType.CLOSED) {
				return Range.atLeast(func.apply(range.lowerEndpoint()));
			}
			return Range.greaterThan(func.apply(range.lowerEndpoint()));
		}
		if (range.hasUpperBound()) {
			if (range.upperBoundType() == BoundType.CLOSED) {
				return Range.atMost(func.apply(range.upperEndpoint()));
			}
			return Range.lessThan(func.apply(range.upperEndpoint()));
		}
		return Range.all();
	}

	protected static <N extends Number & Comparable<N>> Double minWithSlack(Double a, N b) {
		if (a == null) {
			if (b == null) {
				return null;
			}
			return b.doubleValue() - SLACK;
		}
		if (b == null) {
			return a;
		}
		return Math.min(a, b.doubleValue() - SLACK);
	}

	protected static <N extends Number & Comparable<N>> Double maxWithSlack(Double a, N b) {
		if (a == null) {
			if (b == null) {
				return null;
			}
			return b.doubleValue() + SLACK;
		}
		if (b == null) {
			return a;
		}
		return Math.max(a, b.doubleValue() + SLACK);
	}

	// TODO: Consider using a "TimelineCellRenderer"
	public interface TimelineInfo<T, N extends Number & Comparable<N>> {
		Range<N> getRange(T t);

		default String getLabel(T t) {
			return t.toString();
		}

		default boolean columnAffectsBounds(int column) {
			return true;
		}

		default Color getForegroundColor(T t, JComponent in, int track, boolean selected,
				boolean hasFocus) {
			if (selected) {
				return UIManagerWrapper.getColor("Table[Enabled+Selected].textForeground");
			}
			return UIManagerWrapper.getColor("Table.textForeground");
		}

		default Color getBackgroundColor(T t, JComponent in, int track, boolean selected,
				boolean hasFocus) {
			if (selected) {
				return UIManagerWrapper.getColor("Table[Enabled+Selected].textBackground");
			}
			if (track % 2 == 1) {
				return UIManagerWrapper.getColor("Table.alternateRowColor");
			}
			return UIManagerWrapper.getColor("Table:\"Table.cellRenderer\".background");
		}

		default JComponent getComponent(T t) {
			String text = getLabel(t);
			JLabel label = new JLabel(text);
			label.setToolTipText(text);
			label.setHorizontalAlignment(SwingConstants.CENTER);
			return label;
		}
	}

	protected static class BoundTypeBorder implements Border {
		protected final Insets unboundedInsets = new Insets(INSET_WIDTH, 0, INSET_WIDTH, 0);
		protected final Insets rightBoundedInsets =
			new Insets(INSET_WIDTH, 0, INSET_WIDTH, INSET_WIDTH);
		protected final Insets leftBoundedInsets =
			new Insets(INSET_WIDTH, INSET_WIDTH, INSET_WIDTH, 0);
		protected final Insets boundedInsets =
			new Insets(INSET_WIDTH, INSET_WIDTH, INSET_WIDTH, INSET_WIDTH);
		protected final Range<?> range;

		public BoundTypeBorder(Range<?> range) {
			this.range = range;
		}

		@Override
		public void paintBorder(Component c, Graphics g, int x1, int y1, int width, int height) {
			Graphics2D solid = (Graphics2D) g.create();
			solid.setStroke(new BasicStroke(3));
			solid.setColor(c.getForeground());
			Graphics2D dashed = (Graphics2D) solid.create();
			dashed.setStroke(new BasicStroke(3, BasicStroke.CAP_SQUARE, BasicStroke.JOIN_MITER,
				1.0f, new float[] { 3, 3 }, 0));

			int x2 = x1 + width - 1;
			int y2 = y1 + height - 1;

			// Adjust for width
			// TODO: Make this configurable
			x1++;
			y1++;
			x2--;
			y2--;

			// Top and bottom lines are always drawn
			solid.drawLine(x1, y1, x2, y1);
			solid.drawLine(x1, y2, x2, y2);

			if (range.hasLowerBound()) {
				if (range.lowerBoundType() == BoundType.CLOSED) {
					solid.drawLine(x1, y1, x1, y2);
				}
				else {
					dashed.drawLine(x1, y1, x1, y2);
				}
			}
			if (range.hasUpperBound()) {
				if (range.upperBoundType() == BoundType.CLOSED) {
					solid.drawLine(x2, y1, x2, y2);
				}
				else {
					dashed.drawLine(x2, y1, x2, y2);
				}
			}
		}

		@Override
		public Insets getBorderInsets(Component c) {
			if (range.hasLowerBound()) {
				if (range.hasUpperBound()) {
					return boundedInsets;
				}
				return leftBoundedInsets;
			}
			if (range.hasUpperBound()) {
				return rightBoundedInsets;
			}
			return unboundedInsets;
		}

		@Override
		public boolean isBorderOpaque() {
			return true;
		}
	}

	protected static class TimelineTrackLayout<N extends Number & Comparable<N>>
			implements LayoutManager2 {
		protected final TimelineTrack<?, N> track;
		protected final Map<Component, Range<N>> components = new HashMap<>();

		public TimelineTrackLayout(TimelineTrack<?, N> track) {
			this.track = track;
		}

		@Override
		public void addLayoutComponent(String name, Component comp) {
			throw new UnsupportedOperationException();
		}

		@Override
		@SuppressWarnings("unchecked") // Used only internally
		public void addLayoutComponent(Component comp, Object constraints) {
			components.put(comp, (Range<N>) constraints);
		}

		@Override
		public void removeLayoutComponent(Component comp) {
			components.remove(comp);
		}

		@Override
		public Dimension preferredLayoutSize(Container parent) {
			double length = track.viewRange.upperEndpoint() - track.viewRange.lowerEndpoint();
			Dimension result = new Dimension();
			for (Entry<Component, Range<N>> ent : components.entrySet()) {
				Range<Double> tRange = mapRangeEndpoints(ent.getValue(), Number::doubleValue);
				if (!tRange.isConnected(track.viewRange)) {
					continue;
				}
				Dimension size = ent.getKey().getMinimumSize();
				Range<Double> subRange = track.viewRange.intersection(tRange);
				double subLength = subRange.upperEndpoint() - subRange.lowerEndpoint();
				if (subLength != 0) {
					double fraction = subLength / length;
					result.width = Math.max(result.width, (int) Math.ceil(size.width / fraction));
				}
				result.height = Math.max(result.height, size.height);
			}
			return result;
		}

		@Override
		public Dimension minimumLayoutSize(Container parent) {
			return new Dimension(0, 0);
		}

		@Override
		public void layoutContainer(Container parent) {
			Dimension pDim = parent.getSize();
			double length = track.viewRange.upperEndpoint() - track.viewRange.lowerEndpoint();
			Rectangle cur = new Rectangle();
			cur.y = 0;
			cur.height = pDim.height;
			for (Entry<Component, Range<N>> ent : components.entrySet()) {
				Range<Double> tRange = mapRangeEndpoints(ent.getValue(), Number::doubleValue);
				if (!tRange.isConnected(track.viewRange)) {
					ent.getKey().setBounds(-10, -10, 1, 1); // Nowhere
					continue;
				}
				Range<Double> range = track.viewRange.intersection(tRange);
				double subLength = range.upperEndpoint() - range.lowerEndpoint();
				double subLeft = range.lowerEndpoint() - track.viewRange.lowerEndpoint();
				cur.x = (int) (subLeft / length * pDim.width);
				cur.width = Math.max(INSET_WIDTH * 3, (int) (subLength / length * pDim.width));
				ent.getKey().setBounds(cur);
			}
		}

		@Override
		public Dimension maximumLayoutSize(Container target) {
			return new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE);
		}

		@Override
		public float getLayoutAlignmentX(Container target) {
			return 0.5f;
		}

		@Override
		public float getLayoutAlignmentY(Container target) {
			return 0.5f;
		}

		@Override
		public void invalidateLayout(Container target) {
			// No cache to clear
		}
	}

	protected static class TimelineTrack<T, N extends Number & Comparable<N>> extends JPanel {
		protected final RangeMap<N, T> objects = TreeRangeMap.create();
		protected final BiMap<T, JComponent> componentMap = HashBiMap.create();
		protected final TimelineInfo<T, N> info;
		protected final MouseListener mouseListener;
		protected final FocusListener focusListener;
		protected boolean isCompressed;

		protected Range<Double> viewRange = Range.closed(-1.0, 1.0);

		public TimelineTrack(TimelineInfo<T, N> info, MouseListener mouseListener,
				FocusListener focusListener, boolean isCompressed) {
			this.info = info;
			this.mouseListener = mouseListener;
			this.focusListener = focusListener;
			this.isCompressed = isCompressed;
			setLayout(new TimelineTrackLayout<>(this));
			setFocusable(true);
		}

		@Override
		public boolean isOpaque() {
			return super.isOpaque();
		}

		public void setViewRange(Range<Double> viewRange) {
			this.viewRange = viewRange;
			invalidate();
		}

		public boolean fits(Range<N> range) {
			if (isCompressed) {
				return objects.subRangeMap(range).asMapOfRanges().isEmpty();
			}
			return false;
		}

		public void add(Range<N> range, T t) {
			objects.put(range, t);
			JComponent comp = info.getComponent(t);
			comp.setOpaque(true);
			comp.setFocusable(true);
			comp.addMouseListener(mouseListener);
			comp.addFocusListener(focusListener);
			add(comp, range);
			componentMap.put(t, comp);
		}

		public void remove(T t) {
			Range<N> found = null;
			for (Entry<Range<N>, T> ent : objects.asMapOfRanges().entrySet()) {
				if (ent.getValue().equals(t)) {
					found = ent.getKey();
					break; // I'm assert each value is unique
				}
			}
			if (found != null) {
				objects.remove(found);
				Component comp = componentMap.remove(t);
				remove(comp);
			}
		}

		public void removeAll(Collection<T> c) {
			RangeSet<N> found = TreeRangeSet.create();
			for (Entry<Range<N>, T> ent : objects.asMapOfRanges().entrySet()) {
				if (c.contains(ent.getValue())) {
					found.add(ent.getKey());
				}
			}
			for (Range<N> range : found.asRanges()) {
				objects.remove(range);
			}
		}

		public boolean isEmpty() {
			return objects.asMapOfRanges().isEmpty();
		}
	}

	protected class ItemTracker {
		private final List<T> trackedItems = new ArrayList<>();

		public List<T> itemsInserted(int firstIndex, int lastIndex) {
			synchronized (tableModel) {
				List<T> inserted =
					new ArrayList<>(tableModel.getModelData().subList(firstIndex, lastIndex + 1));
				trackedItems.addAll(firstIndex, inserted);
				assert Objects.equals(tableModel.getModelData(), trackedItems);
				return inserted;
			}
		}

		public List<T> itemsUpdated(int firstIndex, int lastIndex) {
			synchronized (tableModel) {
				List<T> updated = new ArrayList<>(lastIndex - firstIndex + 1);
				for (int i = firstIndex; i <= lastIndex; i++) {
					T t = tableModel.getModelData().get(i);
					updated.add(t);
					trackedItems.set(i, t);
				}
				assert Objects.equals(tableModel.getModelData(), trackedItems);
				return updated;
			}
		}

		public List<T> itemsDeleted(int firstIndex, int lastIndex) {
			synchronized (tableModel) {
				List<T> sub = trackedItems.subList(firstIndex, lastIndex + 1);
				List<T> deleted = new ArrayList<>(sub);
				sub.clear();
				assert Objects.equals(tableModel.getModelData(), trackedItems);
				return deleted;
			}
		}

		public List<T> itemsRefreshed() {
			synchronized (tableModel) {
				trackedItems.clear();
				trackedItems.addAll(tableModel.getModelData());
				return trackedItems;
			}
		}

		public void clear() {
			trackedItems.clear();
		}

		public List<T> items() {
			return trackedItems;
		}
	}

	protected class CellMouseListener extends MouseAdapter {

		@Override
		public void mouseClicked(MouseEvent e) {
			Component cell = e.getComponent();
			cell.requestFocus(Cause.MOUSE_EVENT);
			@SuppressWarnings("unchecked")
			TimelineTrack<T, N> track = (TimelineTrack<T, N>) cell.getParent();
			T t = track.componentMap.inverse().get(cell);
			assert t != null;

			int index = rows.items().indexOf(t); // Ew. Why does filtered model not use view
			if (e.isControlDown()) {
				if (selectionModel.isSelectedIndex(index)) {
					selectionModel.removeSelectionInterval(index, index);
				}
				else {
					selectionModel.addSelectionInterval(index, index);
				}
			}
			else {
				selectionModel.setSelectionInterval(index, index);
			}
			timelineListeners.fire.itemActivated(index);
		}
	}

	protected class CellFocusListener extends FocusAdapter {
		@Override
		public void focusGained(FocusEvent e) {
			focusGainedOrLost();
		}

		@Override
		public void focusLost(FocusEvent e) {
			focusGainedOrLost();
		}
	}

	protected RowObjectTableModel<T> tableModel;
	protected ListSelectionModel selectionModel;
	protected TimelineInfo<T, N> info;
	protected Range<Double> viewRange = Range.closed(-1.0, 1.0);
	protected double maxAtLeast;
	private boolean isCompressed = true;

	protected final TableModelListener tableModelListener = this::tableChanged;
	protected final ListSelectionListener selectionModelListener = this::selectionChanged;
	protected final ItemTracker rows = new ItemTracker();
	protected final List<TimelineTrack<T, N>> tracks = new ArrayList<>();
	protected final Map<T, TimelineTrack<T, N>> trackMap = new HashMap<>();
	protected final ListenerSet<TimelineListener> timelineListeners =
		new ListenerSet<>(TimelineListener.class);
	protected final MouseListener mouseListener = new CellMouseListener();
	protected final FocusListener focusListener = new CellFocusListener();

	public TimelinePanel() {
		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
		setFocusable(true);
	}

	public TimelinePanel(RowObjectTableModel<T> model, TimelineInfo<T, N> info) {
		this();
		setTableModel(model, info);
		setSelectionModel(new DefaultListSelectionModel());
	}

	private synchronized void focusGainedOrLost() {
		recolor(); // TODO: Way too draconian
	}

	public void addTimelineListener(TimelineListener listener) {
		timelineListeners.add(listener);
	}

	public void removeTimelineListener(TimelineListener listener) {
		timelineListeners.remove(listener);
	}

	protected Range<Double> computeViewRange() {
		// TODO: Optimize when adding if performance is an issue
		Double min = null;
		double max = maxAtLeast + SLACK;
		// Don't use Range's union/span methods, since I need to ignore unbounded ends
		for (TimelineTrack<T, N> track : tracks) {
			for (Range<N> range : track.objects.asMapOfRanges().keySet()) {
				N lower = range.hasLowerBound() ? range.lowerEndpoint() : null;
				N upper = range.hasUpperBound() ? range.upperEndpoint() : null;
				min = minWithSlack(min, lower);
				min = minWithSlack(min, upper);
				max = maxWithSlack(max, lower);
				max = maxWithSlack(max, upper);
			}
		}
		if (min == null) {
			min = 0.0;
		}
		return Range.closed(min, max);
	}

	protected synchronized void reSortTracks() {
		// TODO: Can I be more selective about which tracks are involved?
		BiMap<TimelineTrack<T, N>, Integer> minIndices = HashBiMap.create(tracks.size());
		List<T> items = rows.items();
		for (int i = 0; i < items.size(); i++) {
			final int fi = i;
			minIndices.compute(trackMap.get(items.get(i)),
				(t, j) -> j == null ? fi : Math.min(fi, j));
		}
		tracks.sort((t1, t2) -> Integer.compare(minIndices.get(t1), minIndices.get(t2)));
		this.removeAll();
		for (TimelineTrack<T, N> track : tracks) {
			add(track);
		}
	}

	protected synchronized void assignTrack(T t) {
		Range<N> range = info.getRange(t);
		for (TimelineTrack<T, N> track : tracks) {
			if (track.fits(range)) {
				track.add(range, t);
				trackMap.put(t, track);
				return;
			}
		}
		TimelineTrack<T, N> track =
			new TimelineTrack<>(info, mouseListener, focusListener, isCompressed);
		add(track);
		tracks.add(track);
		track.add(range, t);
		trackMap.put(t, track);
	}

	protected synchronized void assignTracks(Collection<T> col) {
		for (T t : col) {
			assert !trackMap.containsKey(t);
			assignTrack(t);
		}
	}

	protected synchronized void adjustTrack(T t) {
		Range<N> range = info.getRange(t);
		TimelineTrack<T, N> track = trackMap.get(t);
		track.remove(t);
		if (track.fits(range)) {
			track.add(range, t);
			return;
		}
		assignTrack(t);
	}

	protected synchronized Component getComponent(T key) {
		return trackMap.get(key).componentMap.get(key);
	}

	protected synchronized void reAssignTracks() {
		for (T t : rows.items()) { // Prefer to move earlier rows to the top tracks
			TimelineTrack<T, N> fromTrack = trackMap.get(t);
			for (TimelineTrack<T, N> toTrack : tracks) {
				Range<N> range = info.getRange(t);
				if (toTrack.fits(range)) {
					fromTrack.remove(t);
					toTrack.add(range, t);
					trackMap.put(t, toTrack);
					break;
				}
				if (fromTrack == toTrack) {
					break; // Just leave in current track
				}
			}
		}
		for (Iterator<TimelineTrack<T, N>> it = tracks.iterator(); it.hasNext();) {
			TimelineTrack<T, N> track = it.next();
			if (track.isEmpty()) {
				it.remove();
				remove(track);
			}
		}
	}

	protected synchronized void adjustTracks(Collection<T> col) {
		for (T t : col) {
			adjustTrack(t);
		}
		reAssignTracks(); // TODO: Could become inefficient....
	}

	protected synchronized void cleanTracks(Collection<T> col) {
		for (TimelineTrack<T, N> track : tracks) {
			track.removeAll(col);
		}
		trackMap.keySet().removeAll(col);
		reAssignTracks();
	}

	private synchronized void tableChanged(TableModelEvent e) {
		switch (e.getType()) {
			case TableModelEvent.INSERT:
				List<T> itemsInserted = rows.itemsInserted(e.getFirstRow(), e.getLastRow());
				assignTracks(itemsInserted);
				reSortTracks();
				fitView();
				recolor();
				break;
			case TableModelEvent.UPDATE:
				if (e.getLastRow() >= tableModel.getRowCount()) {
					reload();
					fitView();
					recolor();
				}
				else {
					int column = e.getColumn();
					if (info.columnAffectsBounds(column)) {
						List<T> itemsUpdated = rows.itemsUpdated(e.getFirstRow(), e.getLastRow());
						adjustTracks(itemsUpdated);
						reSortTracks();
						fitView();
						recolor();
					}
				}
				break;
			case TableModelEvent.DELETE:
				List<T> itemsDeleted = rows.itemsDeleted(e.getFirstRow(), e.getLastRow());
				cleanTracks(itemsDeleted);
				reSortTracks();
				fitView();
				recolor();
				break;
		}
	}

	protected void removeOldTableModelListeners() {
		if (tableModel == null) {
			return;
		}
		tableModel.removeTableModelListener(tableModelListener);
	}

	protected void addNewTableModelListeners() {
		if (tableModel == null) {
			return;
		}
		tableModel.addTableModelListener(tableModelListener);
	}

	public synchronized RowObjectTableModel<T> getTableModel() {
		return tableModel;
	}

	public synchronized void setTableModel(RowObjectTableModel<T> model, TimelineInfo<T, N> info) {
		if (this.tableModel == model) {
			return;
		}
		removeOldTableModelListeners();
		clear();

		this.tableModel = model;
		this.info = info;
		addNewTableModelListeners();

		reload();
		fitView();
	}

	protected void selectionChanged(ListSelectionEvent e) {
		recolor();
	}

	protected void removeOldSelectionModelListeners() {
		if (selectionModel == null) {
			return;
		}
		selectionModel.removeListSelectionListener(selectionModelListener);
	}

	protected void addNewSelectionModelListeners() {
		selectionModel.addListSelectionListener(selectionModelListener);
	}

	public synchronized void setSelectionModel(ListSelectionModel selectionModel) {
		if (this.selectionModel == selectionModel) {
			return;
		}
		removeOldSelectionModelListeners();

		this.selectionModel =
			selectionModel == null ? new DefaultListSelectionModel() : selectionModel;
		addNewSelectionModelListeners();

		recolor();
	}

	protected synchronized void clear() {
		this.rows.clear();
		this.tracks.clear();
		this.trackMap.clear();
		this.removeAll();
	}

	protected synchronized void reload() {
		clear();
		if (tableModel == null) {
			return;
		}
		assignTracks(rows.itemsRefreshed());
		recolor();
	}

	protected synchronized void recolor() {
		//dumpkeys(Border.class, Border::toString);
		List<T> items = rows.items();
		for (int i = 0; i < items.size(); i++) {
			T t = items.get(i);
			boolean selected = selectionModel.isSelectedIndex(i);
			TimelineTrack<T, N> track = trackMap.get(t);
			JComponent comp = track.componentMap.get(t);
			boolean hasFocus = comp.hasFocus();
			// TODO: I'd rather not use indexOf, but I suppose I shouldn't expect many tracks?
			Color bg = info.getBackgroundColor(t, comp, tracks.indexOf(track), selected, hasFocus);
			Color fg = info.getForegroundColor(t, comp, tracks.indexOf(track), selected, hasFocus);
			comp.setBackground(bg);
			comp.setForeground(fg);
			BoundTypeBorder rangeBorder = new BoundTypeBorder(info.getRange(t));
			Border uiBorder = UIManagerWrapper.getBorder(
				hasFocus ? "Table.focusCellHighlightBorder" : "Table.cellNoFocusBorder");
			Border border = BorderFactory.createCompoundBorder(rangeBorder, uiBorder);
			comp.setBorder(border);
		}
		repaint();
	}

	protected void fitView() {
		Range<Double> newViewRange = computeViewRange();
		if (this.viewRange.equals(newViewRange)) {
			validate();
			return;
		}
		this.viewRange = newViewRange;
		for (TimelineTrack<T, N> track : tracks) {
			track.setViewRange(newViewRange);
		}
		validate();
		timelineListeners.fire.viewRangeChanged(newViewRange);
	}

	public Range<Double> getViewRange() {
		return viewRange;
	}

	protected <C> void dumpkeys(Class<C> cls, Function<C, String> fmt) { // For debugging and experimentation
		TreeMap<Object, C> sorted = new TreeMap<>();
		UIManager.getDefaults()
				.entrySet()
				.stream()
				.filter(ent -> cls.isInstance(ent.getValue()))
				.forEach(ent -> sorted.put(ent.getKey(), cls.cast(ent.getValue())));
		for (Entry<Object, C> ent : sorted.entrySet()) {
			System.out.println(String.format("%s=%s", ent.getKey(), fmt.apply(ent.getValue())));
		}
	}

	public void setMaxAtLeast(double maxAtLeast) {
		if (this.maxAtLeast == maxAtLeast) {
			return;
		}
		this.maxAtLeast = maxAtLeast;
		if (!viewRange.contains(maxAtLeast + SLACK)) {
			Swing.runIfSwingOrRunLater(() -> fitView());
		}
	}

	public double getMaxAtLeast() {
		return maxAtLeast;
	}

	public boolean isCompressed() {
		return isCompressed;
	}

	public void setCompressed(boolean isCompressed) {
		this.isCompressed = isCompressed;
	}

	/**
	 * Get the cell bounds, relative to the timeline, of the given item
	 * 
	 * @param t the item
	 * @return the rectangle, or {@code null} if the given item is not present
	 */
	public synchronized Rectangle getCellBounds(T t) {
		TimelineTrack<T, N> track = trackMap.get(t);
		if (track == null) {
			return null;
		}
		JComponent comp = track.componentMap.get(t);
		if (comp == null) {
			return null;
		}
		Rectangle bounds = comp.getBounds();
		Point tl = track.getLocation();
		bounds.x += tl.x;
		bounds.y += tl.y;
		return bounds;
	}
}
