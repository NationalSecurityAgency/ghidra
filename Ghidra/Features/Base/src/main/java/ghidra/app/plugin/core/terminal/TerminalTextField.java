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
package ghidra.app.plugin.core.terminal;

import java.awt.*;
import java.util.List;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.field.FieldElement;
import docking.widgets.fieldpanel.field.TextField;
import docking.widgets.fieldpanel.internal.FieldBackgroundColorManager;
import docking.widgets.fieldpanel.internal.PaintContext;
import docking.widgets.fieldpanel.support.*;
import ghidra.app.plugin.core.terminal.vt.*;

/**
 * A text field (renderer) for the terminal panel.
 * 
 * <p>
 * The purpose of this thing is to hold a single text field element. It is also responsible for
 * rendering selections and the cursor. Because the cursor is also supposed to be controlled by the
 * application, we do less "validation" and correction of it on our end. If it's past the end of a
 * line, so be it.
 */
public class TerminalTextField implements TextField {
	protected final int startX;
	protected final TerminalTextFieldElement element;
	protected final int em;

	protected boolean isPrimary;

	/**
	 * Create a text field for the given line.
	 * 
	 * <p>
	 * This method will create the sole text field element populating this field.
	 * 
	 * @param line the line from the {@link VtBuffer} that will be rendered in this field
	 * @param metrics the font metrics
	 * @param colors the color resolver
	 * @return the field
	 */
	public static TerminalTextField create(VtLine line, FontMetrics metrics,
			AnsiColorResolver colors) {
		return new TerminalTextField(0, new TerminalTextFieldElement(line, metrics, colors),
			metrics);
	}

	protected TerminalTextField(int startX, TerminalTextFieldElement element, FontMetrics metrics) {
		this.startX = startX;
		this.element = element;
		this.em = metrics.charWidth('M');
	}

	@Override
	public void paint(JComponent c, Graphics g, PaintContext context, Rectangle clip,
			FieldBackgroundColorManager colorManager, RowColLocation cursorLoc, int rowHeight) {
		if (context.isPrinting()) {
			print(g, context);
		}
		else {
			paintSelection(g, colorManager, 0, rowHeight);
			paintText(c, g, context);
			paintCursor(g, context.getCursorColor(), cursorLoc);
		}
	}

	protected void print(Graphics g, PaintContext context) {
		element.paint(null, g, startX, 0);
	}

	protected void paintText(JComponent c, Graphics g, PaintContext context) {
		element.paint(c, g, startX, 0);
	}

	protected void paintSelection(Graphics g, FieldBackgroundColorManager colorManager, int row,
			int rowHeight) {
		List<Highlight> selections = colorManager.getSelectionHighlights(row);
		if (selections.isEmpty()) {
			return;
		}
		int textLength = element.length();
		int endTextPos = findX(textLength);
		for (Highlight highlight : selections) {
			g.setColor(highlight.getColor());
			int startCol = highlight.getStart();
			int endCol = highlight.getEnd();
			int x1 = findX(startCol);
			int x2 = endCol < element.length() ? findX(endCol) : endTextPos;
			g.fillRect(startX + x1, -getHeightAbove(), x2 - x1, getHeight());
		}

		// Padding?
	}

	/**
	 * Paint a big cursor, so people can actually see it. Also, don't check column number. The
	 * cursor is frequently past the end of the text, e.g., after pressing space in vim.
	 */
	protected void paintCursor(Graphics g, Color cursorColor, RowColLocation cursorLoc) {
		if (cursorLoc != null) {
			g.setColor(cursorColor);
			int x = startX + findX(cursorLoc.col());
			g.drawRect(x, -getHeightAbove(), em - 1, getHeight() - 1);
			// This technique looks ugly with display scaling
			//g.drawRect(x + 1, -getHeightAbove() + 1, em - 3, getHeight() - 3);
		}
	}

	protected int findX(int col) {
		return em * col;
	}

	@Override
	public int getWidth() {
		return element.getStringWidth();
	}

	@Override
	public int getPreferredWidth() {
		return element.getStringWidth();
	}

	@Override
	public int getHeight() {
		return element.getHeightAbove() + element.getHeightBelow();
	}

	@Override
	public int getHeightAbove() {
		return element.getHeightAbove();
	}

	@Override
	public int getHeightBelow() {
		return element.getHeightBelow();
	}

	@Override
	public int getStartX() {
		return startX;
	}

	@Override
	public boolean contains(int x, int y) {
		return (x >= startX) && (x < startX + getWidth()) && (y >= -element.getHeightAbove()) &&
			(y < element.getHeightBelow());
	}

	@Override
	public int getNumDataRows() {
		return 1;
	}

	@Override
	public int getNumRows() {
		return 1;
	}

	@Override
	public int getNumCols(int row) {
		return element.getNumCols();
	}

	@Override
	public int getX(int row, int col) {
		return startX + findX(col);
	}

	@Override
	public int getY(int row) {
		return -getHeightAbove();
	}

	@Override
	public int getRow(int y) {
		return 0;
	}

	@Override
	public int getCol(int row, int x) {
		int relX = Math.max(0, x - startX);
		return element.getMaxCharactersForWidth(relX);
	}

	@Override
	public boolean isValid(int row, int col) {
		return row == 0 && 0 <= col && col < getNumCols(0);
	}

	@Override
	public Rectangle getCursorBounds(int row, int col) {
		if (row != 0) {
			return null;
		}

		int x = findX(col) + startX;
		return new Rectangle(x, -getHeightAbove(), em, getHeight());
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
	public void setPrimary(boolean isPrimary) {
		this.isPrimary = isPrimary;
	}

	@Override
	public boolean isPrimary() {
		return isPrimary;
	}

	@Override
	public void rowHeightChanged(int heightAbove, int heightBelow) {
		// Don't care
	}

	@Override
	public String getText() {
		return element.getText();
	}

	@Override
	public String getTextWithLineSeparators() {
		return element.getText();
	}

	@Override
	public RowColLocation textOffsetToScreenLocation(int textOffset) {
		// allow the max position to be just after the last character
		return new RowColLocation(0, Math.min(textOffset, element.length()));
	}

	@Override
	public int screenLocationToTextOffset(int row, int col) {
		return Math.min(element.length(), col);
	}

	@Override
	public RowColLocation screenToDataLocation(int screenRow, int screenColumn) {
		return element.getDataLocationForCharacterIndex(screenColumn);
	}

	@Override
	public RowColLocation dataToScreenLocation(int dataRow, int dataColumn) {
		int column = element.getCharacterIndexForDataLocation(dataRow, dataColumn);
		if (column < 0) {
			return new DefaultRowColLocation(0, element.length());
		}
		return new RowColLocation(0, column);
	}

	@Override
	public boolean isClipped() {
		return false;
	}

	@Override
	public FieldElement getFieldElement(int screenRow, int screenColumn) {
		return element.getFieldElement(screenColumn);
	}
}
