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

import com.google.common.collect.Range;

public class RangeCursorTableHeaderRenderer<N extends Number & Comparable<N>>
		extends GTableHeaderRenderer {
	protected final static int ARROW_SIZE = 10;
	protected final static Polygon ARROW = new Polygon(
		new int[] { 0, -ARROW_SIZE, -ARROW_SIZE },
		new int[] { 0, ARROW_SIZE, -ARROW_SIZE }, 3);

	protected Range<Double> fullRange = Range.closed(0d, 1d);
	protected double span = 1;

	protected N pos;
	protected double doublePos;

	public void setFullRange(Range<N> fullRange) {
		this.fullRange = RangeTableCellRenderer.validateViewRange(fullRange);
		this.span = this.fullRange.upperEndpoint() - this.fullRange.lowerEndpoint();
	}

	public void setCursorPosition(N pos) {
		this.pos = pos;
		this.doublePos = pos.doubleValue();
	}

	@Override
	protected void paintChildren(Graphics g) {
		super.paintChildren(g);
		paintCursor(g);
	}

	protected void paintCursor(Graphics parentG) {
		Graphics2D g = (Graphics2D) parentG.create();

		g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
		double x = (doublePos - fullRange.lowerEndpoint()) / span * getWidth();
		g.translate(x, getHeight());
		g.rotate(Math.PI / 2);
		g.setColor(getForeground());
		g.fillPolygon(ARROW);
	}

	public void addSeekListener(JTable table, int modelColumn, Consumer<Double> listener) {
		TableColumnModel colModel = table.getColumnModel();
		JTableHeader header = table.getTableHeader();
		TableColumn col = colModel.getColumn(modelColumn);
		MouseAdapter l = new MouseAdapter() {
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
				if (header.getResizingColumn() != null) {
					return;
				}
				int viewColIdx = colModel.getColumnIndexAtX(e.getX());
				int modelColIdx = table.convertColumnIndexToModel(viewColIdx);
				if (modelColIdx != modelColumn) {
					return;
				}

				TableColumn draggedCol = header.getDraggedColumn();
				if (draggedCol == col) {
					header.setDraggedColumn(null);
				}
				else if (draggedCol != null) {
					return;
				}

				int colX = 0;
				for (int i = 0; i < viewColIdx; i++) {
					colX += colModel.getColumn(i).getWidth();
				}
				TableColumn col = colModel.getColumn(viewColIdx);

				double pos = span * (e.getX() - colX) / col.getWidth() + fullRange.lowerEndpoint();
				listener.accept(pos);
			}
		};
		header.addMouseListener(l);
		header.addMouseMotionListener(l);
	}

	public N getCursorPosition() {
		return pos;
	}
}
