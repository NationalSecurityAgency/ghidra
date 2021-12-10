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
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.JComponent;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.fieldpanel.internal.FieldBackgroundColorManager;
import docking.widgets.fieldpanel.internal.PaintContext;
import docking.widgets.fieldpanel.support.*;
import generic.json.Json;

/**
 * A {@link TextField} that takes in other TextFields.
 * 
 * <P>This class allows clients to create custom text layout behavior by combining individual
 * TextFields that dictate layout behavior.  As an example, consider this rendering:
 * <pre>
 * 	1)  This is some text...
 * 	2)	This
 * 		is
 * 		more
 * 		text
 * </pre>
 * In this example, 1) is a row of text inside of a {@link ClippingTextField}.  Row 2) is a
 * multi-line text rendering specified in a single {@link FlowLayoutTextField}, using a
 * narrow width to trigger the field to place each element on its own line.
 */
public class CompositeVerticalLayoutTextField implements TextField {

	// the view rows, which may be a clipped version of the client fields
	private List<FieldRow> fieldRows;
	private int startX;
	private int width;
	private int preferredWidth;
	private HighlightFactory hlFactory;

	private int height;
	private int heightAbove;
	private int numRows;
	private int numDataRows;
	private boolean isPrimary;

	private String fullText;

	// all text, including any clipped text;  lines.size() == fields.size()
	private List<String> lines;

	// used in the getText() method to separate rows without adding newlines
	private String rowSeparator;

	private boolean isClipped;

	public CompositeVerticalLayoutTextField(List<TextField> fields, int startX, int width,
			int maxLines, HighlightFactory hlFactory) {
		this(fields, startX, width, maxLines, hlFactory, " ");
	}

	protected CompositeVerticalLayoutTextField(List<TextField> fields, int startX, int width,
			int maxLines, HighlightFactory hlFactory, String rowSeparator) {

		this.startX = startX;
		this.width = width;

		this.hlFactory = hlFactory;
		this.rowSeparator = rowSeparator;

		lines = generateLines(fields);
		fullText = generateText(fields, rowSeparator);

		heightAbove = (fields.get(0)).getHeightAbove();
		fieldRows = layoutRows(fields, maxLines);

		calculateRows(fields);
		calculatePreferredWidth();
		calculateHeight();
	}

	private List<String> generateLines(List<TextField> fields) {

		List<String> list = new ArrayList<>();
		for (TextField field : fields) {
			list.add(field.getTextWithLineSeparators());
		}
		return list;
	}

	private String generateText(List<TextField> fields, String delimiter) {

		StringBuilder buf = new StringBuilder();
		for (TextField element : fields) {
			buf.append(element.getText()).append(delimiter);
		}
		return buf.toString();
	}

	private List<FieldRow> layoutRows(List<TextField> fields, int maxLines) {

		List<FieldRow> newSubFields = new ArrayList<>();
		int startY = -heightAbove;
		int ySoFar = startY;
		int currentRow = 0;
		boolean tooManyLines = fields.size() > maxLines;
		for (int i = 0; i < fields.size() && i < maxLines; i++) {
			TextField field = fields.get(i);
			if (tooManyLines && (i == maxLines - 1)) {
				FieldElement element = field.getFieldElement(0, 0);
				TextField newField = createClippedField(element);
				newSubFields.add(new FieldRow(newField, currentRow, ySoFar));
				isClipped = true;
			}
			else {
				newSubFields.add(new FieldRow(field, currentRow, ySoFar));
				isClipped |= field.isClipped();
			}

			ySoFar += field.getHeight();
			currentRow += field.getNumRows();
		}

		isClipped |= tooManyLines;

		return newSubFields;
	}

	private ClippingTextField createClippedField(FieldElement element) {

		FieldElement[] elements = new FieldElement[] {
			element,
			new StrutFieldElement(500)
		};
		FieldElement compositeElement = new CompositeFieldElement(elements);
		return new ClippingTextField(startX, width, compositeElement, hlFactory);
	}

	private void calculateHeight() {
		for (FieldRow row : fieldRows) {
			height += row.field.getHeight();
		}
	}

	private void calculatePreferredWidth() {
		preferredWidth = 0;
		for (FieldRow row : fieldRows) {
			preferredWidth = Math.max(preferredWidth, row.field.getPreferredWidth());
		}
	}

	private void calculateRows(List<TextField> fields) {
		numRows = 0;
		for (FieldRow row : fieldRows) {
			numRows += row.field.getNumRows();
		}

		numDataRows = 0;
		for (TextField field : fields) {
			numDataRows += field.getNumDataRows();
		}
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
	public int getNumDataRows() {
		return numDataRows;
	}

	@Override
	public int getNumRows() {
		return numRows;
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
	public boolean isPrimary() {
		return isPrimary;
	}

	@Override
	public void rowHeightChanged(int newHeightAbove, int newHeightBelow) {
		// don't care
	}

	@Override
	public boolean isClipped() {
		return isClipped;
	}

	@Override
	public void setPrimary(boolean state) {
		isPrimary = state;
	}

	@Override
	public String getText() {
		return fullText;
	}

	@Override
	public String getTextWithLineSeparators() {
		return StringUtils.join(lines, '\n');
	}

	@Override
	public void paint(JComponent c, Graphics g, PaintContext context, Rectangle clip,
			FieldBackgroundColorManager colorManager, RowColLocation cursorLocation,
			int rowHeight) {

		// the graphics have been translated such that the first line of text's base line is
		// at y=0  (So if we are not clipped, we will drawing from a negative value that is the
		// font's height above the baseline (-heightAbove) to rowHeight (-heightAbove)
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

		FieldRow cursorRow = null;
		if (cursorLocation != null) {
			cursorRow = getFieldRow(cursorLocation.row());
		}

		int startY = myStartY;
		int translatedY = 0;

		for (int i = 0; i < fieldRows.size(); i++) {

			// if past clipping region we are done
			if (startY > clipEndY) {
				break;
			}

			FieldRow fieldRow = fieldRows.get(i);
			TextField field = fieldRow.field;
			int subFieldHeight = fieldRow.field.getHeight();
			int endY = startY + subFieldHeight;

			// if any part of the line is in the clip region, draw it
			if (endY >= clipStartY) {
				RowColLocation cursor = null;
				if (fieldRow == cursorRow) {
					int relativeRow = fieldRow.getRelativeRow(cursorLocation.row());
					cursor = cursorLocation.withRow(relativeRow);
				}

				field.paint(c, g, context, clip, colorManager, cursor, rowHeight);
			}

			// translate for next row of text
			startY += subFieldHeight;
			g.translate(0, subFieldHeight);
			translatedY += subFieldHeight;
		}

		// restore the graphics to where it was when we started.
		g.translate(0, -translatedY);
	}

	@Override
	public boolean contains(int x, int y) {
		if ((x >= startX) && (x < startX + width) && (y >= -heightAbove) &&
			(y < height - heightAbove)) {
			return true;
		}
		return false;
	}

	public String getRowSeparator() {
		return rowSeparator;
	}

	private FieldRow getFieldRow(int screenRow) {
		int currentRow = 0;
		for (FieldRow row : fieldRows) {
			int n = row.field.getNumRows();
			if (currentRow + n > screenRow) {
				return row;
			}
			currentRow += n;
		}
		return fieldRows.get(fieldRows.size() - 1);
	}

	private FieldRow getFieldRowFromDataRow(int dataRow) {

		int currentRow = 0;
		for (FieldRow row : fieldRows) {
			int length = row.field.getNumDataRows();

			if (currentRow + length > dataRow) {
				return row;
			}
			currentRow += length;
		}
		return fieldRows.get(fieldRows.size() - 1);
	}

	// get all rows from 0 to max inclusive
	private List<FieldRow> getAllRows(int maxRow) {
		int currentRow = 0;
		List<FieldRow> list = new ArrayList<>();
		for (FieldRow row : fieldRows) {
			if (currentRow > maxRow) {
				break;
			}

			list.add(row);
			currentRow += row.field.getNumRows();
		}
		return list;
	}

	// for testing
	protected List<TextField> getAllRowsUpTo(int maxRowInclusive) {
		return getAllRows(maxRowInclusive)
				.stream()
				.map(fieldRow -> fieldRow.field)
				.collect(Collectors.toList());
	}

	@Override
	public FieldElement getFieldElement(int screenRow, int screenColumn) {
		FieldRow fieldRow = getFieldRow(screenRow);
		int relativeRow = fieldRow.getRelativeRow(screenRow);
		return fieldRow.field.getFieldElement(relativeRow, screenColumn);
	}

	@Override
	public int getNumCols(int row) {
		FieldRow fieldRow = getFieldRow(row);
		int relativeRow = fieldRow.getRelativeRow(row);
		return fieldRow.field.getNumCols(relativeRow);
	}

	@Override
	public int getX(int row, int col) {
		FieldRow fieldRow = getFieldRow(row);
		int relativeRow = fieldRow.getRelativeRow(row);
		return fieldRow.field.getX(relativeRow, col);
	}

	@Override
	public int getY(int row) {

		int startY = -heightAbove;
		int ySoFar = startY;
		List<FieldRow> rows = getAllRows(row);
		int lastHeight = 0;
		for (FieldRow fieldRow : rows) {
			ySoFar += lastHeight;
			if (fieldRow.displayRowOffset >= row) {
				return ySoFar;
			}
			lastHeight = fieldRow.field.getHeight();
		}

		return ySoFar;
	}

	@Override
	public int getRow(int y) {

		// our start y value is our baseline - the heigh above the baseline
		int startY = -heightAbove;
		if (y < startY) {
			return 0;
		}

		int ySoFar = startY;

		for (FieldRow fieldRow : fieldRows) {
			int fieldHeight = fieldRow.field.getHeight();
			int bottom = fieldHeight + ySoFar;
			if (bottom > y) {
				int relativeY = y - ySoFar;
				int relativeRow = fieldRow.field.getRow(relativeY);
				int displayRow = fieldRow.fromRelativeRow(relativeRow);
				return displayRow;
			}
			ySoFar += fieldHeight;
		}
		return getNumRows() - 1;
	}

	@Override
	public int getCol(int row, int x) {

		FieldRow fieldRow = getFieldRow(row);
		int relativeRow = fieldRow.getRelativeRow(row);
		return fieldRow.field.getCol(relativeRow, x);
	}

	@Override
	public boolean isValid(int row, int col) {

		if ((row < 0) || (row >= getNumRows())) {
			return false;
		}

		FieldRow fieldRow = getFieldRow(row);
		int relativeRow = fieldRow.getRelativeRow(row);
		return fieldRow.field.isValid(relativeRow, col);
	}

	@Override
	public Rectangle getCursorBounds(int row, int col) {

		if ((row < 0) || (row >= getNumRows())) {
			return null;
		}

		List<FieldRow> rows = getAllRows(row);
		FieldRow cursorRow = rows.get(rows.size() - 1);
		int relativeRow = cursorRow.getRelativeRow(row);
		Rectangle r = cursorRow.field.getCursorBounds(relativeRow, col);

		for (int i = 0; i < rows.size() - 1; i++) {
			FieldRow previousRow = rows.get(i);
			r.y += previousRow.field.getHeight();
		}
		return r;
	}

	@Override
	public int getScrollableUnitIncrement(int topOfScreen, int direction, int max) {

		if ((topOfScreen < -heightAbove) || (topOfScreen > height - heightAbove)) {
			return max;
		}

		int row = getRow(topOfScreen);
		int y = getY(row);
		int rowOffset = topOfScreen - y;
		FieldRow fieldRow = getFieldRow(row);
		int rowHeight = fieldRow.field.getHeight();
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
	public RowColLocation screenToDataLocation(int screenRow, int screenColumn) {

		screenRow = Math.min(screenRow, numRows - 1);
		screenRow = Math.max(screenRow, 0);

		FieldRow fieldRow = getFieldRow(screenRow);

		screenColumn = Math.min(screenColumn, fieldRow.field.getText().length());
		screenColumn = Math.max(screenColumn, 0);

		int relativeRow = fieldRow.getRelativeRow(screenRow);
		return fieldRow.field.screenToDataLocation(relativeRow, screenColumn);
	}

	@Override
	public RowColLocation dataToScreenLocation(int dataRow, int dataColumn) {
		FieldRow fieldRow = getFieldRowFromDataRow(dataRow);
		RowColLocation location = fieldRow.field.dataToScreenLocation(dataRow, dataColumn);
		int relativeRow = fieldRow.fromRelativeRow(location.row());
		return location.withRow(relativeRow);
	}

	@Override
	public int screenLocationToTextOffset(int row, int col) {

		if (row >= numRows) {
			return getText().length();
		}

		int extraSpace = rowSeparator.length();
		int len = 0;
		List<FieldRow> rows = getAllRows(row);
		int n = rows.size() - 1;
		for (int i = 0; i < n; i++) {
			FieldRow fieldRow = rows.get(i);
			len += fieldRow.field.getText().length() + extraSpace;
		}

		FieldRow lastRow = rows.get(n);
		int relativeRow = lastRow.getRelativeRow(row);
		len += lastRow.field.screenLocationToTextOffset(relativeRow, col);
		return len;
	}

	@Override
	public RowColLocation textOffsetToScreenLocation(int textOffset) {

		int extraSpace = rowSeparator.length();
		int n = fieldRows.size();
		int textOffsetSoFar = 0;
		for (int i = 0; i < n; i++) {

			if (textOffsetSoFar > textOffset) {
				break;
			}

			FieldRow fieldRow = fieldRows.get(i);
			int length = fieldRow.field.getText().length() + extraSpace;
			int end = textOffsetSoFar + length;
			if (end > textOffset) {
				int relativeOffset = textOffset - textOffsetSoFar;
				RowColLocation location = fieldRow.field.textOffsetToScreenLocation(relativeOffset);
				int screenRow = fieldRow.fromRelativeRow(location.row());
				return location.withRow(screenRow);
			}

			textOffsetSoFar += length;
		}

		FieldRow lastRow = fieldRows.get(fieldRows.size() - 1);
		int length = lastRow.field.getText().length();
		return new DefaultRowColLocation(numRows - 1, length);
	}

	private class FieldRow {
		private TextField field;
		private int displayRowOffset;
		private int yOffset;

		FieldRow(TextField field, int rowOffset, int yOffset) {
			this.field = field;
			this.displayRowOffset = rowOffset;
		}

		// used to turn given row into 0 for this composite field
		int getRelativeRow(int displayRow) {
			return displayRow - displayRowOffset;
		}

		int fromRelativeRow(int relativeRow) {
			return relativeRow + displayRowOffset;
		}

		int getY() {
			return yOffset;
		}

		@Override
		public String toString() {
			return Json.toString(this);
		}
	}
}
