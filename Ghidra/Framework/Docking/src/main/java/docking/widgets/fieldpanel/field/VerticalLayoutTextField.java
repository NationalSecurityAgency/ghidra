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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.internal.FieldBackgroundColorManager;
import docking.widgets.fieldpanel.internal.PaintContext;
import docking.widgets.fieldpanel.support.*;

/**
 * This class provides a TextField implementation that takes multiple FieldElements and places
 * each on its own line within the field.  It also can take a single FieldElements and 
 * word wrap,creating new FieldElements (one per line).
 */
public class VerticalLayoutTextField implements TextField {

	protected FieldElement[] textElements;
	protected List<Field> subFields;  // list of fields for FieldElements
	protected int startX;
	protected int width;
	protected int preferredWidth;
	protected HighlightFactory hlFactory;

	private int height;
	private int heightAbove;
	private boolean isPrimary;
	private String text;

	protected boolean isClipped;
	private String lineDelimiter; // used in the getText() method to separate lines

	/**
	 * This constructor will create a text field from an array of FieldElements, putting each
	 * element on its own line.
	 * 
	 * @param textElements the FieldElements to display
	 * @param startX  the x position to draw the element
	 * @param width   the max width allocated to this field
	 * @param maxLines the max number of lines to display
	 * @param hlFactory the highlight factory
	 */
	public VerticalLayoutTextField(FieldElement[] textElements, int startX, int width, int maxLines,
			HighlightFactory hlFactory) {
		this(textElements, startX, width, maxLines, hlFactory, " ");
	}

	/**
	 * This constructor will create a text field from an array of FieldElements, putting each
	 * element on its own line.
	 * 
	 * @param textElements the FieldElements to display
	 * @param startX  the x position to draw the element
	 * @param width   the max width allocated to this field
	 * @param maxLines the max number of lines to display
	 * @param hlFactory the highlight factory
	 * @param lineDelimiter The string to space lines of text when concatenated by the 
	 *        getText() method.
	 */
	protected VerticalLayoutTextField(FieldElement[] textElements, int startX, int width,
			int maxLines, HighlightFactory hlFactory, String lineDelimiter) {

		this.textElements = textElements;
		this.startX = startX;
		this.width = width;

		this.hlFactory = hlFactory;
		this.lineDelimiter = lineDelimiter;

		subFields = layoutElements(maxLines);

		this.preferredWidth = calculatePreferredWidth();
		calculateHeight();
	}

	protected void calculateHeight() {
		heightAbove = (subFields.get(0)).getHeightAbove();
		for (Field field : subFields) {
			height += field.getHeight();
		}
	}

	private int calculatePreferredWidth() {
		int widest = 0;
		for (Field field : subFields) {
			widest = Math.max(widest, field.getPreferredWidth());
		}
		return widest;
	}

	@Override
	public String getText() {
		if (text == null) {
			text = generateText();
		}
		return text;
	}

	@Override
	public String getTextWithLineSeparators() {
		return generateText("\n");
	}

	@Override
	public String toString() {
		return getText();
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
	public int getHeight() {
		return height;
	}

	@Override
	public int getStartX() {
		return startX;
	}

	@Override
	public int getNumRows() {
		return subFields.size();
	}

	@Override
	public int getNumCols(int row) {
		Field f = subFields.get(row);
		return f.getNumCols(0);
	}

	@Override
	public int getRow(int y) {
		if (y < -heightAbove) {
			return 0;
		}
		int heightSoFar = -heightAbove;

		int n = subFields.size();
		for (int i = 0; i < n; i++) {
			Field f = subFields.get(i);
			heightSoFar += f.getHeight();
			if (heightSoFar > y) {
				return i;
			}
		}
		return n - 1;
	}

	@Override
	public int getCol(int row, int x) {
		Field f = subFields.get(row);
		return f.getCol(0, x);
	}

	@Override
	public int getY(int row) {

		int y = -heightAbove;
		for (int i = 0; i < row; i++) {
			Field f = subFields.get(row);
			y += f.getHeight();
		}
		return y;
	}

	@Override
	public int getX(int row, int col) {
		Field f = subFields.get(row);
		return f.getX(0, col);
	}

	@Override
	public boolean isValid(int row, int col) {

		if ((row < 0) || (row >= subFields.size())) {
			return false;
		}
		Field f = subFields.get(row);
		return f.isValid(0, col);
	}

	@Override
	public void paint(JComponent c, Graphics g, PaintContext context,
			Rectangle clip, FieldBackgroundColorManager colorManager, RowColLocation cursorLoc,
			int rowHeight) {
		if (context.isPrinting()) {
			print(g, context);
			return;
		}

		int cursorTextOffset = -1;
		int cursorRow = -1;
		if (cursorLoc != null) {
			cursorTextOffset = screenLocationToTextOffset(cursorLoc.row(), cursorLoc.col());
			cursorRow = cursorLoc.row();
		}

		Highlight[] highlights = hlFactory.getHighlights(this, getText(), cursorTextOffset);
		int columns = 0;
		int n = subFields.size();

		// the graphics have been translated such that the first line of text's base line is
		// at y=0  (So if we are not clipped, we will drawing from negative the fonts height above
		// the baseline (-heightAbove) to rowHeight -heightAbove
		int myStartY = -heightAbove;
		int myEndY = myStartY + rowHeight;
		int clipStartY = clip.y;
		int clipEndY = clip.y + clip.height;

		Color fieldBackgroundColor = colorManager.getBackgroundColor();
		if (fieldBackgroundColor != null) {
			g.setColor(fieldBackgroundColor);

			// restrict background rectangle to clipping rectangle
			int startY = Math.max(myStartY, clipStartY);
			int endY = Math.min(myEndY, clipEndY);
			int clippedHeight = endY - startY;
			g.fillRect(startX, startY, width, clippedHeight);
		}

		int startY = myStartY;
		int translatedY = 0;

		for (int i = 0; i < n; i++) {
			ClippingTextField subField = (ClippingTextField) subFields.get(i);
			int subFieldHeight = subField.getHeight();
			int endY = startY + subFieldHeight;

			// if past clipping region we are done
			if (startY > clipEndY) {
				break;
			}

			// if any part of the line is in the clip region, draw it
			if (endY >= clipStartY) {
				// translate the highlights
				for (Highlight highlight : highlights) {
					highlight.setOffset(-columns);
				}
				subField.paintSelection(g, colorManager, i, rowHeight);
				subField.paintHighlights(g, highlights);
				subField.paintText(c, g, context);
				if (cursorRow == i) {
					subField.paintCursor(g, context.getCursorColor(), cursorLoc);
				}
			}

			// translate for next row of text
			startY += subFieldHeight;
			g.translate(0, subFieldHeight);
			translatedY += subFieldHeight;
			columns += subField.getText().length() + lineDelimiter.length();
		}

		// restore the graphics to where it was when we started.
		g.translate(0, -translatedY);
	}

	private void print(Graphics g, PaintContext context) {
		int n = subFields.size();
		for (int i = 0; i < n; i++) {
			ClippingTextField clippingField = (ClippingTextField) subFields.get(i);

			clippingField.print(g, context);

			g.translate(0, clippingField.getHeight());
		}
		g.translate(0, -height);
	}

	@Override
	public Rectangle getCursorBounds(int row, int col) {
		if ((row < 0) || (row >= subFields.size())) {
			return null;
		}
		Field f = subFields.get(row);
		Rectangle r = f.getCursorBounds(0, col);
		for (int i = 0; i < row; i++) {
			f = subFields.get(row);
			r.y += f.getHeight();
		}
		return r;
	}

	@Override
	public boolean contains(int x, int y) {
		if ((x >= startX) && (x < startX + width) && (y >= -heightAbove) &&
			(y < height - heightAbove)) {
			return true;
		}
		return false;
	}

	@Override
	public int getScrollableUnitIncrement(int topOfScreen, int direction, int max) {

		if ((topOfScreen < -heightAbove) || (topOfScreen > height - heightAbove)) {
			return max;
		}
		int row = getRow(topOfScreen);
		int y = getY(row);
		int rowOffset = topOfScreen - y;
		int rowHeight = (subFields.get(row)).getHeight();
		if (direction > 0) { // if scrolling down
			return rowHeight - rowOffset;
		}
		else if (rowOffset == 0) {
			return -rowHeight;
		}
		else {
			return -rowOffset;
		}
	}

	@Override
	public boolean isPrimary() {
		return isPrimary;
	}

	/**
	 * Sets the primary State.
	 * @param state the state to set.
	 */
	@Override
	public void setPrimary(boolean state) {
		isPrimary = state;
	}

	/**
	 * Returns the list of subfields in this field.
	 */
	public List<Field> getSubfields() {
		return Collections.unmodifiableList(subFields);
	}

	@Override
	public int getHeightAbove() {
		return heightAbove;
	}

	@Override
	public int getHeightBelow() {
		return height - heightAbove;
	}

	@Override
	public void rowHeightChanged(int heightAbove1, int heightBelow) {
		// most fields don't care		
	}

	@Override
	public FieldElement getFieldElement(int screenRow, int screenColumn) {

		FieldElement clickedField = textElements[screenRow];
		return clickedField.getFieldElement(screenColumn);
	}

	protected List<Field> layoutElements(int maxLines) {
		List<Field> newSubFields = new ArrayList<>();

		boolean tooManyLines = textElements.length > maxLines;

		for (int i = 0; i < textElements.length && i < maxLines; i++) {
			FieldElement element = textElements[i];
			if (tooManyLines && (i == maxLines - 1)) {
				FieldElement[] elements = new FieldElement[2];
				elements[0] = element;
				elements[1] = new EmptyFieldElement(500);
				element = new CompositeFieldElement(elements);
			}
			TextField field = new ClippingTextField(startX, width, element, hlFactory);
			newSubFields.add(field);
			isClipped |= field.isClipped();
		}

		isClipped |= tooManyLines;

		return newSubFields;
	}

	/**
	 * Translates the row and column to a String index and character offset into 
	 * that string.
	 * @param screenRow the row containing the location.
	 * @param screenColumn the character position in the row of the location
	 * @return a MultiStringLocation containing the string index and position 
	 * within that string.
	 */
	@Override
	public RowColLocation screenToDataLocation(int screenRow, int screenColumn) {

		screenRow = Math.min(screenRow, textElements.length - 1);
		screenRow = Math.max(screenRow, 0);

		screenColumn = Math.min(screenColumn, textElements[screenRow].length());
		screenColumn = Math.max(screenColumn, 0);

		return textElements[screenRow].getDataLocationForCharacterIndex(screenColumn);
	}

	/**
	 * Finds the corresponding row, column for string index, and offset
	 * @param dataRow index into the string array
	 * @param dataColumn offset into the indexed string.
	 */
	@Override
	public RowColLocation dataToScreenLocation(int dataRow, int dataColumn) {
		for (int screenRow = textElements.length - 1; screenRow >= 0; screenRow--) {
			FieldElement element = textElements[screenRow];
			int screenColumn = element.getCharacterIndexForDataLocation(dataRow, dataColumn);
			if (screenColumn >= 0) {
				return new RowColLocation(screenRow, screenColumn);
			}
		}

		return new RowColLocation(0, 0); // give up
	}

	protected String generateText() {
		return generateText(lineDelimiter);
	}

	protected String generateText(String delimiter) {
		StringBuffer buf = new StringBuffer();
		int n = textElements.length - 1;
		for (int i = 0; i < n; i++) {
			buf.append(textElements[i].getText()).append(delimiter);
		}
		buf.append(textElements[n].getText());
		return buf.toString();
	}

	@Override
	public int screenLocationToTextOffset(int row, int col) {
		if (row >= textElements.length) {
			return getText().length();
		}
		int extraSpace = lineDelimiter.length();
		int len = 0;
		for (int i = 0; i < row; i++) {
			len += textElements[i].getText().length() + extraSpace;
		}
		len += Math.min(col, textElements[row].getText().length());
		return len;
	}

	@Override
	public RowColLocation textOffsetToScreenLocation(int textOffset) {
		int extraSpace = lineDelimiter.length();
		int n = textElements.length;
		for (int i = 0; i < n; i++) {
			int len = textElements[i].getText().length();
			if (textOffset < len + extraSpace) {
				return new RowColLocation(i, textOffset);
			}
			textOffset -= len + extraSpace;
		}
		return new RowColLocation(n - 1, textElements[n - 1].getText().length());
	}

	@Override
	public boolean isClipped() {
		return isClipped;
	}
}
