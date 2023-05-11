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
package docking.widgets.table;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.function.Consumer;

import javax.swing.JTable;
import javax.swing.table.*;

import generic.Span;
import ghidra.util.datastruct.ListenerSet;

public class RangeCursorTableHeaderRenderer<N extends Number & Comparable<N>>
		extends GTableHeaderRenderer implements SpannedRenderer<N> {

	public interface SeekListener extends Consumer<Double> {
	}

	protected class ForSeekMouseListener extends MouseAdapter {

		@Override
		public void mouseClicked(MouseEvent e) {
			if ((e.getModifiersEx() & MouseEvent.SHIFT_DOWN_MASK) != 0) {
				return;
			}
			if ((e.getButton() != MouseEvent.BUTTON1)) {
				return;
			}
			doSeek(e);
			e.consume();
		}

		@Override
		public void mouseDragged(MouseEvent e) {
			int onmask = MouseEvent.BUTTON1_DOWN_MASK;
			int offmask = MouseEvent.SHIFT_DOWN_MASK;
			if ((e.getModifiersEx() & (onmask | offmask)) != onmask) {
				return;
			}
			doSeek(e);
			e.consume();
		}

		protected void doSeek(MouseEvent e) {
			TableColumnModel colModel = savedTable.getColumnModel();
			JTableHeader header = savedTable.getTableHeader();
			TableColumn myViewCol = colModel.getColumn(savedViewColumn);
			if (header.getResizingColumn() != null) {
				return;
			}
			int clickedViewColIdx = colModel.getColumnIndexAtX(e.getX());
			if (clickedViewColIdx != savedViewColumn) {
				return;
			}

			TableColumn draggedViewCol = header.getDraggedColumn();
			if (draggedViewCol == myViewCol) {
				header.setDraggedColumn(null);
			}
			else if (draggedViewCol != null) {
				return;
			}

			int colX = 0;
			for (int i = 0; i < clickedViewColIdx; i++) {
				colX += colModel.getColumn(i).getWidth();
			}

			double pos =
				span * (e.getX() - colX) / myViewCol.getWidth() + fullRangeDouble.min();
			listeners.fire.accept(pos);
		}
	}

	protected final static int ARROW_SIZE = 10;
	protected final static Polygon ARROW = new Polygon(
		new int[] { 0, -ARROW_SIZE, -ARROW_SIZE },
		new int[] { 0, ARROW_SIZE, -ARROW_SIZE }, 3);

	protected DoubleSpan fullRangeDouble = new DoubleSpan(0d, 1d);
	protected double span = 1;

	protected Span<N, ?> fullRange;

	protected N pos;
	protected double doublePos;

	private JTable savedTable;
	private int savedViewColumn;

	private final ForSeekMouseListener forSeekMouseListener = new ForSeekMouseListener();
	private final ListenerSet<SeekListener> listeners = new ListenerSet<>(SeekListener.class);

	public RangeCursorTableHeaderRenderer(N pos) {
		this.pos = pos;
	}

	@Override
	public void setFullRange(Span<N, ?> fullRange) {
		this.fullRangeDouble = SpannedRenderer.validateViewRange(fullRange);
		this.span = this.fullRangeDouble.max() - this.fullRangeDouble.min();
	}

	public void setCursorPosition(N pos) {
		this.pos = pos;
		this.doublePos = pos.doubleValue();
	}

	protected void setSavedTable(JTable table) {
		if (savedTable != null) {
			JTableHeader header = savedTable.getTableHeader();
			header.removeMouseListener(forSeekMouseListener);
			header.removeMouseMotionListener(forSeekMouseListener);
		}
		savedTable = table;
		if (savedTable != null) {
			JTableHeader header = savedTable.getTableHeader();
			header.addMouseListener(forSeekMouseListener);
			header.addMouseMotionListener(forSeekMouseListener);
		}
	}

	@Override
	public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
			boolean hasFocus, int row, int column) {
		setSavedTable(table);
		savedViewColumn = column;
		return super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
	}

	@Override
	protected void paintChildren(Graphics g) {
		super.paintChildren(g);
		// The cursor should occlude the children
		paintCursor(g);
	}

	protected void paintCursor(Graphics parentG) {
		Graphics2D g = (Graphics2D) parentG.create();

		g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
		double x = (doublePos - fullRangeDouble.min()) / span * getWidth();
		g.translate(x, getHeight());
		g.rotate(Math.PI / 2);
		g.setColor(getForeground());
		g.fillPolygon(ARROW);
	}

	public void addSeekListener(SeekListener listener) {
		listeners.add(listener);
	}

	public N getCursorPosition() {
		return pos;
	}

	@Override
	public Span<N, ?> getFullRange() {
		return fullRange;
	}

	@Override
	public DoubleSpan getFullRangeDouble() {
		return fullRangeDouble;
	}

	@Override
	public double getSpan() {
		return span;
	}
}
