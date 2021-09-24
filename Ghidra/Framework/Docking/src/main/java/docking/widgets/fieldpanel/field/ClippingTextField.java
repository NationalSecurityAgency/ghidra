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

import docking.widgets.fieldpanel.internal.FieldBackgroundColorManager;
import docking.widgets.fieldpanel.internal.PaintContext;
import docking.widgets.fieldpanel.support.*;

/**
 * Field for showing multiple strings, each with its own attributes in a field,
 * on a single line, clipping as needed to fit within the field's width. Has the
 * extra methods for mapping column positions to strings and positions in those
 * strings.
 */
public class ClippingTextField implements TextField {
	private static int DOT_DOT_DOT_WIDTH = 12;

	private FieldElement originalElement;
	private FieldElement textElement;

	protected int startX;
	private int width;
	private int preferredWidth;
	private int numDataRows;

	private String fullText;
	private boolean isClipped;

	private HighlightFactory hlFactory;

	private boolean isPrimary;

	/**
	 * Constructs a new ClippingTextField that allows the cursor beyond the end
	 * of the line.
	 * 
	 * @param startX The x position of the field
	 * @param width The width of the field
	 * @param textElement The AttributedStrings to display in the field.
	 * @param hlFactory The HighlightFactory object used to paint highlights.
	 */
	public ClippingTextField(int startX, int width, FieldElement textElement,
			HighlightFactory hlFactory) {
		// default to one row
		this(startX, width, textElement, 1, hlFactory);
	}

	/**
	 * Constructs a new ClippingTextField that allows the cursor beyond the end
	 * of the line.
	 * 
	 * <p>This constructor allows clients to specify the number of data rows that have been
	 * converted into a single screen row.
	 * 
	 * @param startX The x position of the field
	 * @param width The width of the field
	 * @param textElement The AttributedStrings to display in the field.
	 * @param numDataRows the number of data rows represented by this single screen row field
	 * @param hlFactory The HighlightFactory object used to paint highlights.
	 */
	public ClippingTextField(int startX, int width, FieldElement textElement, int numDataRows,
			HighlightFactory hlFactory) {

		this.startX = startX;
		this.width = width;
		this.numDataRows = numDataRows;
		this.textElement = textElement;
		this.hlFactory = hlFactory;
		this.preferredWidth = textElement.getStringWidth();

		clip(width);
	}

	/**
	 * Checks if any of the textElements need to be clipped. If so, it creates a
	 * new textElement for the element that needs to be clipped that will fit in
	 * the available space. Any textElements past the clipped element will be
	 * ignored.
	 */
	private void clip(int availableWidth) {
		originalElement = textElement;
		int w = textElement.getStringWidth();

		if (w <= availableWidth) {
			return;
		}

		isClipped = true;
		int length = textElement.getMaxCharactersForWidth(width - DOT_DOT_DOT_WIDTH);
		textElement = textElement.substring(0, length);
	}

	@Override
	public boolean contains(int x, int y) {
		if ((x >= startX) && (x < startX + width) && (y >= -textElement.getHeightAbove()) &&
			(y < textElement.getHeightBelow())) {
			return true;
		}
		return false;
	}

	@Override
	public int getCol(int row, int x) {
		int xPos = Math.max(x - startX, 0); // make x relative to this fields coordinate system
		return textElement.getMaxCharactersForWidth(xPos);
	}

	@Override
	public Rectangle getCursorBounds(int row, int col) {
		if (row != 0) {
			return null;
		}

		int x = findX(col) + startX;

		return new Rectangle(x, -textElement.getHeightAbove(), 2,
			textElement.getHeightAbove() + textElement.getHeightBelow());
	}

	@Override
	public int getHeight() {
		return textElement.getHeightAbove() + textElement.getHeightBelow();
	}

	@Override
	public int getNumCols(int row) {
		return getNumCols();
	}

	private int getNumCols() {
		// allow one column past the end of the text to allow the cursor to be placed after the text
		return textElement.length() + 1;
	}

	@Override
	public int getNumDataRows() {
		return numDataRows;
	}

	@Override
	public int getNumRows() {
		return 1;
	}

	@Override
	public int getRow(int y) {
		return 0;
	}

	@Override
	public int getScrollableUnitIncrement(int topOfScreen, int direction, int max) {

		if ((topOfScreen < -getHeightAbove()) || (topOfScreen > getHeightBelow())) {
			return max;
		}

		if (direction > 0) { // if scrolling down
			return getHeightBelow() - topOfScreen;
		}

		return -getHeightAbove() - topOfScreen;
	}

	@Override
	public int getStartX() {
		return startX;
	}

	@Override
	public int getWidth() {
		return width;
	}

	@Override
	public int getPreferredWidth() {
		return preferredWidth;
	}

	@Override
	public int getX(int row, int col) {
		if (col >= getNumCols()) {
			col = getNumCols() - 1;
		}
		return findX(col) + startX;
	}

	@Override
	public int getY(int row) {
		return -getHeightAbove();
	}

	@Override
	public boolean isPrimary() {
		return isPrimary;
	}

	@Override
	public void setPrimary(boolean b) {
		isPrimary = b;
	}

	@Override
	public boolean isValid(int row, int col) {
		if (row != 0) {
			return false;
		}

		return ((col >= 0) && (col < getNumCols()));
	}

	private String getString() {
		if (fullText == null) {
			fullText = originalElement.getText();
		}
		return fullText;
	}

	@Override
	public void paint(JComponent c, Graphics g, PaintContext context,
			Rectangle clip, FieldBackgroundColorManager colorManager, RowColLocation cursorLoc,
			int rowHeight) {
		if (context.isPrinting()) {
			print(g, context);
		}
		else {
			paintSelection(g, colorManager, 0, rowHeight);
			paintHighlights(g, cursorLoc);
			paintText(c, g, context);
			paintCursor(g, context.getCursorColor(), cursorLoc);
		}
	}

	void print(Graphics g, PaintContext context) {
		// TODO fix printing
		textElement.paint(null, g, startX, 0);
		if (isClipped) {
			paintDots(g, startX + textElement.getStringWidth());
		}

	}

	void paintText(JComponent c, Graphics g, PaintContext context) {
		textElement.paint(c, g, startX, 0);

		if (isClipped) {
			g.setColor(textElement.getColor(textElement.length() - 1));
			paintDots(g, startX + textElement.getStringWidth());
		}
	}

	private void paintDots(Graphics g, int x) {
		int pos = 1; // skip one pixel
		for (int i = 0; i < 3; i++) {
			if (pos < DOT_DOT_DOT_WIDTH - 2) { // don't paint too close to next
				// field.
				g.drawRect(x + pos, -2, 1, 1);
				pos += 4; // add in size of dot and padding
			}
		}
	}

	private void paintHighlights(Graphics g, RowColLocation cursorLoc) {
		int cursorTextOffset = -1;
		if (cursorLoc != null) {
			cursorTextOffset = screenLocationToTextOffset(cursorLoc.row(), cursorLoc.col());
		}
		paintHighlights(g, hlFactory.getHighlights(this, getString(), cursorTextOffset));
	}

	protected void paintSelection(Graphics g, FieldBackgroundColorManager colorManager, int row,
			int rowHeight) {

		List<Highlight> selections = colorManager.getSelectionHighlights(row);
		if (selections.isEmpty()) {
			return;
		}
		int textLength = getString().length();
		int endTextPos = findX(textLength);
		for (Highlight highlight : selections) {
			g.setColor(highlight.getColor());
			int startCol = highlight.getStart();
			int endCol = highlight.getEnd();
			int x1 = findX(startCol);
			int x2 = endCol < textLength ? findX(endCol) : endTextPos;
			g.fillRect(startX + x1, -getHeightAbove(), x2 - x1, getHeight());
		}

		Color rightMarginColor = colorManager.getPaddingColor(1);
		if (rightMarginColor != null) {
			g.setColor(rightMarginColor);
			g.fillRect(startX + endTextPos, -getHeightAbove(), width - endTextPos, rowHeight);
		}
	}

	protected void paintHighlights(Graphics g, Highlight[] highlights) {
		for (Highlight highlight : highlights) {
			int startCol = Math.max(highlight.getStart(), 0);
			int endCol = Math.min(highlight.getEnd(), getString().length());
			Color c = highlight.getColor();
			if (endCol >= startCol) {
				int start = findX(startCol);
				int end = findX(endCol + 1);
				if (isClipped && endCol >= getNumCols()) {
					end += DOT_DOT_DOT_WIDTH;
				}
				g.setColor(c);
				g.fillRect(startX + start, -getHeightAbove(), end - start, getHeight());
			}
		}
	}

	protected void paintCursor(Graphics g, Color cursorColor, RowColLocation cursorLoc) {
		if (cursorLoc != null) {
			g.setColor(cursorColor);
			if (cursorLoc.col() < getNumCols()) {
				int x = startX + findX(cursorLoc.col());
				g.fillRect(x, -getHeightAbove(), 2, getHeight());
			}
		}
	}

	/**
	 * Converts a single column value into a MultiStringLocation which specifies
	 * a string index and a column position within that string.
	 * 
	 * @param screenColumn
	 *            the overall column position in the total String.
	 * @return MultiStringLocation the MultiStringLocation corresponding to the
	 *         given column.
	 */
	@Override
	public RowColLocation screenToDataLocation(int screenRow, int screenColumn) {
		return originalElement.getDataLocationForCharacterIndex(screenColumn);
	}

	@Override
	public RowColLocation dataToScreenLocation(int dataRow, int dataColumn) {
		int column = textElement.getCharacterIndexForDataLocation(dataRow, dataColumn);
		if (column < 0) {
			return new DefaultRowColLocation(0, textElement.length());
		}
		return new RowColLocation(0, column);
	}

	private int findX(int col) {
		if (col > textElement.length()) {
			col = textElement.length();
		}
		return textElement.substring(0, col).getStringWidth();
	}

	/**
	 * Returns true if the text is clipped (truncated)
	 */
	@Override
	public boolean isClipped() {
		return isClipped;
	}

	@Override
	public int getHeightAbove() {
		return textElement.getHeightAbove();
	}

	@Override
	public int getHeightBelow() {
		return textElement.getHeightBelow();
	}

	@Override
	public void rowHeightChanged(int heightAbove, int heightBelow) {
		// Don't care
	}

	@Override
	public String getText() {
		return getString();
	}

	@Override
	public String getTextWithLineSeparators() {
		return getString();
	}

	@Override
	public RowColLocation textOffsetToScreenLocation(int textOffset) {
		// allow the max position to be just after the last character
		return new RowColLocation(0, Math.min(textOffset, textElement.getText().length()));
	}

	@Override
	public int screenLocationToTextOffset(int row, int col) {
		return Math.min(textElement.getText().length(), col);
	}

	public Object getClickedObject(FieldLocation fieldLocation) {
		return getFieldElement(fieldLocation.row, fieldLocation.col);
	}

	@Override
	public FieldElement getFieldElement(int screenRow, int screenColumn) {
		return originalElement.getFieldElement(screenColumn);
	}

	@Override
	public String toString() {
		return getText();
	}
}
