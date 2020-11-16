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
package docking.widgets.fieldpanel.field;

import java.awt.*;
import java.util.List;

import javax.swing.JComponent;

import docking.util.GraphicsUtils;
import docking.widgets.fieldpanel.internal.FieldBackgroundColorManager;
import docking.widgets.fieldpanel.internal.PaintContext;
import docking.widgets.fieldpanel.support.*;

/**
 * The simplest possible Text field.  It does not clip and should only be used
 * when the text values always fit in field.
 */

public class SimpleTextField implements Field {

	protected String text; // the name of this field
	protected FontMetrics metrics;
	protected int startX;
	protected Color foregroundColor;
	protected int width;
	protected int preferredWidth;
	protected int heightAbove;
	protected int heightBelow;
	protected int numCols;
	protected boolean allowCursorAtEnd;
	protected boolean isPrimary;
	protected final HighlightFactory hlFactory;

	/**
	 * Constructs a new SimpleTextField.
	 * @param text The text for the field.
	 * @param fontMetrics the fontMetrics used to render the text.
	 * @param startX the starting x coordinate.
	 * @param width the width of the field.
	 * @param allowCursorAtEnd if true, allows the cursor to go one position past
	 * the end of the text.
	 */
	public SimpleTextField(String text, FontMetrics fontMetrics, int startX, int width,
			boolean allowCursorAtEnd, HighlightFactory hlFactory) {

		this.text = text;
		this.hlFactory = hlFactory;
		this.numCols = text.length();
		if (allowCursorAtEnd) {
			this.numCols++;
		}

		setFontMetrics(fontMetrics);
		this.startX = startX;
		this.width = width;
		this.preferredWidth = fontMetrics.stringWidth(text);
		this.allowCursorAtEnd = allowCursorAtEnd;
	}

	/**
	 * Returns true if the cursor is allow to be position past the last character.
	 */
	public boolean isAllowCursorAtEnd() {
		return allowCursorAtEnd;
	}

	/**
	 * 
	 * @see docking.widgets.fieldpanel.field.Field#getWidth()
	 */
	@Override
	public int getWidth() {
		return width;
	}

	@Override
	public int getPreferredWidth() {
		return preferredWidth;
	}

	/**
	 * 
	 * @see docking.widgets.fieldpanel.field.Field#getHeight()
	 */
	@Override
	public int getHeight() {
		return heightAbove + heightBelow;
	}

	/**
	 * 
	 * @see docking.widgets.fieldpanel.field.Field#getStartX()
	 */
	@Override
	public int getStartX() {
		return startX;
	}

	/**
	 * 
	 * @see docking.widgets.fieldpanel.field.Field#getNumRows()
	 */
	@Override
	public int getNumRows() {
		return 1;
	}

	/**
	 * 
	 * @see docking.widgets.fieldpanel.field.Field#getNumCols(int)
	 */
	@Override
	public int getNumCols(int row) {
		return numCols;
	}

	/**
	 * 
	 * @see docking.widgets.fieldpanel.field.Field#getRow(int)
	 */
	@Override
	public int getRow(int y) {
		return 0;
	}

	/**
	 * 
	 * @see docking.widgets.fieldpanel.field.Field#getCol(int, int)
	 */
	@Override
	public int getCol(int row, int x) {
		if (x < startX) {
			x = startX;
		}
		else if (x >= startX + width) {
			x = startX + width - 1;
		}
		int col = findColumn(text, x - startX);
		if (col >= this.numCols) {
			col = numCols - 1;
		}
		return col;
	}

	/**
	 * 
	 * @see docking.widgets.fieldpanel.field.Field#getY(int)
	 */
	@Override
	public int getY(int row) {
		return -heightAbove;
	}

	/**
	 * 
	 * @see docking.widgets.fieldpanel.field.Field#getX(int, int)
	 */
	@Override
	public int getX(int row, int col) {
		int x = 0;
		if (col < text.length()) {
			x = metrics.stringWidth(text.substring(0, col));
		}
		else {
			x = metrics.stringWidth(text);
		}
		return startX + x;
	}

	/**
	 * 
	 * @see docking.widgets.fieldpanel.field.Field#isValid(int, int)
	 */
	@Override
	public boolean isValid(int row, int col) {

		if (row != 0) {
			return false;
		}
		if ((col < 0) || (col > numCols - 1)) {
			return false;
		}
		return true;
	}

	@Override
	public void paint(JComponent c, Graphics g, PaintContext context,
			Rectangle clip, FieldBackgroundColorManager colorManager, RowColLocation cursorLoc, int rowHeight) {
		paintSelection(g, colorManager, 0);
		paintHighlights(g, hlFactory.getHighlights(this, text, -1));
		g.setFont(metrics.getFont());
		if (foregroundColor == null) {
			foregroundColor = context.getForeground();
		}
		g.setColor(foregroundColor);
		GraphicsUtils.drawString(c, g, text, startX, 0);

		paintCursor(g, context.getCursorColor(), cursorLoc);
	}

	protected void paintSelection(Graphics g, FieldBackgroundColorManager colorManager, int row) {
		List<Highlight> selections = colorManager.getSelectionHighlights(row);
		for (Highlight highlight : selections) {
			g.setColor(highlight.getColor());
			int startCol = highlight.getStart();
			int endCol = highlight.getEnd();
			int x1 = findX(startCol);
			int x2 = endCol >= text.length() ? width : findX(endCol);
			g.fillRect(startX + x1, -getHeightAbove(), x2 - x1, getHeight());
		}
	}

	protected void paintHighlights(Graphics g, Highlight[] highlights) {
		for (Highlight highlight : highlights) {
			int startCol = Math.max(highlight.getStart(), 0);
			int endCol = Math.min(highlight.getEnd(), text.length());
			Color c = highlight.getColor();
			if (endCol >= startCol) {
				int start = findX(startCol);
				int end = findX(endCol + 1);
				g.setColor(c);
				g.fillRect(startX + start, -getHeightAbove(), end - start, getHeight());
			}
		}
	}

	private int findX(int column) {
		return metrics.stringWidth(text.substring(0, column));
	}

	private void paintCursor(Graphics g, Color cursorColor, RowColLocation cursorLoc) {
		if (cursorLoc == null) {
			return;
		}

		if (cursorLoc.col() < numCols) {
			g.setColor(cursorColor);
			int x = startX + metrics.stringWidth(text.substring(0, cursorLoc.col()));
			g.fillRect(x, -heightAbove, 2, heightAbove + heightBelow);
		}
	}

	@Override
	public Rectangle getCursorBounds(int row, int col) {
		if (row != 0) {
			return null;
		}
		int x = startX + metrics.stringWidth(text.substring(0, col));
		return new Rectangle(x, -heightAbove, 2, heightAbove + heightBelow);
	}

	/**
	 * Finds the column position for the given pixel x coordinate in the indicated text string.
	 */
	protected int findColumn(String textString, int x) {
		int startPos = 0;
		int col;
		for (col = 0; col < textString.length(); col++) {
			startPos += metrics.charWidth(textString.charAt(col));
			if (x < startPos) {
				break;
			}
		}
		return col;
	}

	/**
	 * 
	 * @see docking.widgets.fieldpanel.field.Field#contains(int, int)
	 */
	@Override
	public boolean contains(int x, int y) {
		if ((x >= startX) && (x < startX + width) && (y >= -heightAbove) && (y < heightBelow)) {
			return true;
		}
		return false;
	}

	/**
	 * Set the foreground color for this field.
	 * @param color the new foreground color.
	 */
	public void setForeground(Color color) {
		this.foregroundColor = color;
	}

	/**
	 * Get the foreground color.
	 *
	 * @return Color could return null if the setForeground() method was
	 * not called, and if this method is called before the paint() method
	 * was called.
	 */
	public Color getForeground() {
		return foregroundColor;
	}

	/**
	 * 
	 * @see docking.widgets.fieldpanel.field.Field#getScrollableUnitIncrement(int, int, int)
	 */
	@Override
	public int getScrollableUnitIncrement(int topOfScreen, int direction, int max) {
		if ((topOfScreen < -heightAbove) || (topOfScreen > heightBelow)) {
			return max;
		}

		if (direction > 0) { // if scrolling down
			return heightBelow - topOfScreen;
		}
		return -heightAbove - topOfScreen;
	}

	/**
	 * Sets the font metrics
	 * @param metrics the fontmetrics to use.
	 */
	public void setFontMetrics(FontMetrics metrics) {
		this.metrics = metrics;
		heightAbove = metrics.getMaxAscent() + metrics.getLeading();
		heightBelow = metrics.getMaxDescent();
	}

	/**
	 * Get the font metrics for this field.
	 */
	public FontMetrics getFontMetrics() {
		return metrics;
	}

	@Override
	public boolean isPrimary() {
		return isPrimary;
	}

	/**
	 * Sets this primary state of this field.
	 * @param state if true, then makes this field primary.
	 */
	public void setPrimary(boolean state) {
		isPrimary = state;
	}

	@Override
	public int getHeightAbove() {
		return heightAbove;
	}

	@Override
	public int getHeightBelow() {
		return heightBelow;
	}

	@Override
	public void rowHeightChanged(int newHeightAbove, int newHeightBelow) {
		// don't care
	}

	@Override
	public String getText() {
		return text;
	}

	@Override
	public String getTextWithLineSeparators() {
		return text;
	}

	@Override
	public RowColLocation textOffsetToScreenLocation(int textOffset) {
		return new RowColLocation(0, textOffset);
	}

	@Override
	public int screenLocationToTextOffset(int row, int col) {
		return col;
	}

}
