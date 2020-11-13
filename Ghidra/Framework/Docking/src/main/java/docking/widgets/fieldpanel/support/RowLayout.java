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
package docking.widgets.fieldpanel.support;

import java.awt.*;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.internal.FieldBackgroundColorManager;
import docking.widgets.fieldpanel.internal.LayoutBackgroundColorManager;
import docking.widgets.fieldpanel.internal.PaintContext;

/**
 * RowLayout handles a single row layout that may be part of a multiple row layout that
 * is generic enough to be used by the SingleRowLayout or the MultiRowLayout.
 */

public class RowLayout implements Layout {
	private Field[] fields;
	private int heightAbove;
	private int heightBelow;
	private int maxHeightAbove;
	private int lastCursorY;
	private int rowID;
	boolean isPrimary = false;

	/**
	 * Constructs a RowLayout from an array of fields
	 * @param fields the set of fields that make up the entire layout
	 * @param rowID the rowID of this row layout in the overall layout.
	 */
	public RowLayout(Field[] fields, int rowID) {
		this.fields = fields;
		this.rowID = rowID;

		for (Field element : fields) {
			heightAbove = Math.max(heightAbove, element.getHeightAbove());
			heightBelow = Math.max(heightBelow, element.getHeightBelow());
			if (element.isPrimary()) {
				isPrimary = true;
			}
		}
		maxHeightAbove = heightAbove;
		for (Field element : fields) {
			element.rowHeightChanged(heightAbove, heightBelow);
		}
	}

	@Override
	public int getHeight() {
		return heightAbove + heightBelow;
	}

	@Override
	public int getCompressableWidth() {
		//
		// Can only compress the last field, as the rest are potentially part of a grid surrounded
		// by other layouts
		//
		// Notes: we have to account for any offset for fields that are disabled and are in 
		//        the beginning of the row.
		//
		int startX = fields[0].getStartX();
		int rowWidth = startX;

		for (int i = 0; i < fields.length - 1; i++) {
			Field field = fields[i];
			int width = field.getWidth(); // layout manager width
			rowWidth += width;
		}

		Field lastField = fields[fields.length - 1];
		int width = lastField.getWidth();
		int preferredWidth = lastField.getPreferredWidth();
		rowWidth += Math.min(width, preferredWidth);
		return rowWidth;
	}

	/**
	 * Returns the height above the baseline.
	 */
	public int getHeightAbove() {
		return heightAbove;
	}

	/**
	 * Returns the height below the baseline.
	 */
	public int getHeightBelow() {
		return heightBelow;
	}

	/**
	 * Returns the row number of this layout with respect to its containing layout.
	 */
	public int getRowID() {
		return rowID;
	}

	@Override
	public void insertSpaceAbove(int size) {
		heightAbove += size;
	}

	@Override
	public void insertSpaceBelow(int size) {
		heightBelow += size;
	}

	@Override
	public int getNumFields() {
		return fields.length;
	}

	@Override
	public Field getField(int index) {
		return fields[index];
	}

	@Override
	public void paint(JComponent c, Graphics g, PaintContext context, Rectangle rect,
			LayoutBackgroundColorManager colorManager, FieldLocation cursorLocation) {

		if ((rect.y >= heightAbove + heightBelow) || (rect.y + rect.height < 0)) {
			return;
		}

		g.translate(0, heightAbove);
		rect.y -= heightAbove;
		// Draw each actual field
		for (int i = 0; i < fields.length; i++) {
			paintGapSelection(g, colorManager, rect, i);
			RowColLocation cursorLoc = null;
			if (cursorLocation != null && cursorLocation.fieldNum == i) {
				cursorLoc = new RowColLocation(cursorLocation.row, cursorLocation.col);
			}
			FieldBackgroundColorManager fieldColorManager =
				colorManager.getFieldBackgroundColorManager(i);
			paintFieldBackground(g, i, fieldColorManager);
			fields[i].paint(c, g, context, rect, fieldColorManager, cursorLoc, getHeight());
		}
		paintGapSelection(g, colorManager, rect, -1);
		g.translate(0, -heightAbove);
		rect.y += heightAbove;
	}

	private void paintFieldBackground(Graphics g, int fieldNum,
			FieldBackgroundColorManager colorManager) {
		Color fieldBackgroundColor = colorManager.getBackgroundColor();
		if (fieldBackgroundColor == null) {
			return;
		}
		g.setColor(fieldBackgroundColor);
		g.fillRect(fields[fieldNum].getStartX(), -getHeightAbove(), fields[fieldNum].getWidth(),
			getHeight());
	}

	private void paintGapSelection(Graphics g, LayoutBackgroundColorManager colorManager,
			Rectangle rect, int gapIndex) {
		Color gapColor = colorManager.getPaddingColor(gapIndex);
		if (gapColor == null) {
			return;
		}
		if (gapIndex == -1) {
			gapIndex = fields.length;
		}
		int startX =
			gapIndex == 0 ? rect.x : fields[gapIndex - 1].getStartX() +
				fields[gapIndex - 1].getWidth();
		int endX = gapIndex >= fields.length ? rect.x + rect.width : fields[gapIndex].getStartX();

		if (startX < endX) {
			g.setColor(gapColor);
			g.fillRect(startX, -heightAbove, endX - startX, heightAbove + heightBelow);
		}
	}

	@Override
	public int setCursor(FieldLocation cursorLoc, int x, int y) {

		int index = this.findAppropriateFieldIndex(x, y);
		if (index < 0) {
			index = 0;
		}

		Field field = fields[index];

		cursorLoc.fieldNum = index;
		cursorLoc.row = field.getRow(y - heightAbove);
		cursorLoc.col = field.getCol(cursorLoc.row, x);
		return field.getX(cursorLoc.row, cursorLoc.col);
	}

	@Override
	public Rectangle getCursorRect(int fieldNum, int row, int col) {
		if (fieldNum >= fields.length) { // somehow we got a call where this happened
			return null;
		}
		Field field = fields[fieldNum];
		if (field.isValid(row, col)) {
			Rectangle rect = field.getCursorBounds(row, col);
			rect.y += heightAbove;
			return rect;
		}
		return null;
	}

	@Override
	public boolean cursorUp(FieldLocation cursorLoc, int lastX) {
		if (cursorLoc.row > 0) {
			cursorLoc.row--;
			cursorLoc.col = fields[cursorLoc.fieldNum].getCol(cursorLoc.row, lastX);
			return true;
		}
		return false;
	}

	@Override
	public boolean cursorDown(FieldLocation cursorLoc, int lastX) {
		if (cursorLoc.row < fields[cursorLoc.fieldNum].getNumRows() - 1) {
			cursorLoc.row++;
			cursorLoc.col = fields[cursorLoc.fieldNum].getCol(cursorLoc.row, lastX);
			return true;
		}
		return false;
	}

	@Override
	public int cursorBeginning(FieldLocation cursorLoc) {

		Field field = fields[0];

		cursorLoc.row = field.getRow(lastCursorY);
		cursorLoc.col = field.getCol(cursorLoc.row, field.getStartX());
		cursorLoc.fieldNum = 0;
		return field.getX(cursorLoc.row, cursorLoc.col);
	}

	@Override
	public int cursorEnd(FieldLocation cursorLoc) {
		Field field = fields[fields.length - 1];

		cursorLoc.row = field.getRow(lastCursorY);
		cursorLoc.col = field.getCol(cursorLoc.row, field.getStartX() + field.getWidth());
		cursorLoc.fieldNum = fields.length - 1;
		return field.getX(cursorLoc.row, cursorLoc.col);
	}

	@Override
	public int cursorLeft(FieldLocation cursorLoc) {
		if (cursorLoc.col > 0) {
			cursorLoc.col--;
		}
		else { // need to move back one field.
			if (cursorLoc.fieldNum > 0) {
				cursorLoc.fieldNum--;
				Field field = fields[cursorLoc.fieldNum];
				int x = field.getStartX() + field.getWidth() - 1;

				cursorLoc.row = field.getRow(lastCursorY);
				cursorLoc.col = field.getCol(cursorLoc.row, x);
			}
			else if (cursorLoc.row > 0) {
				Field field = fields[cursorLoc.fieldNum];
				cursorLoc.row--;
				cursorLoc.col = field.getNumCols(cursorLoc.row) - 1;
			}
			else {
				return -1;
			}
		}
		return fields[cursorLoc.fieldNum].getX(cursorLoc.row, cursorLoc.col);
	}

	@Override
	public int cursorRight(FieldLocation cursorLoc) {
		if (cursorLoc.col < fields[cursorLoc.fieldNum].getNumCols(cursorLoc.row) - 1) {
			cursorLoc.col++;
		}
		else { // need to move to next field.
			Field field = fields[cursorLoc.fieldNum];
			if (cursorLoc.fieldNum < fields.length - 1) {
				cursorLoc.fieldNum++;
				field = fields[cursorLoc.fieldNum];
				cursorLoc.row = field.getRow(lastCursorY);
				cursorLoc.col = field.getCol(cursorLoc.row, field.getStartX());
			}
			else if (cursorLoc.row < field.getNumRows() - 1) {
				cursorLoc.row++;
				cursorLoc.col = 0;
			}
			else {
				return -1;
			}
		}
		return fields[cursorLoc.fieldNum].getX(cursorLoc.row, cursorLoc.col);
	}

	@Override
	public boolean enterLayout(FieldLocation cursorLoc, int lastX, boolean fromTop) {
		// locate the field that the cursor will enter
		int y = fromTop ? 0 : heightAbove + heightBelow - 1;
		int index = findAppropriateFieldIndex(lastX, y);
		if (index < 0) {
			return false;
		}
		cursorLoc.fieldNum = index;
		Field field = fields[index];

		int x = lastX;
		y = fromTop ? -field.getHeightAbove() : field.getHeightBelow() - 1;

		cursorLoc.row = field.getRow(y);
		cursorLoc.col = field.getCol(cursorLoc.row, x);
		lastCursorY = y;
		return true;

	}

	@Override
	public int getScrollableUnitIncrement(int topOfScreen, int direction) {
		int max = 0;
		if (direction > 0) { // if scrolling down
			if (topOfScreen < heightAbove - maxHeightAbove) {
				return heightAbove - maxHeightAbove - topOfScreen;
			}
			max = heightAbove + heightBelow - topOfScreen;
		}
		else {
			max = -topOfScreen;
		}

		int localTopOfScreen = topOfScreen - heightAbove; //adjust to field coordinates
		for (Field element : fields) {
			if (element != null) {
				int x = element.getScrollableUnitIncrement(localTopOfScreen, direction, max);
				if ((direction > 0) && (x > 0) && (x < max)) {
					max = x;
				}
				else if ((direction < 0) && (x < 0) && (x > max)) {
					max = x;
				}
			}
		}

		return max;
	}

	@Override
	public boolean contains(int yPos) {
		if ((yPos >= 0) && (yPos < heightAbove + heightBelow)) {
			return true;
		}
		return false;
	}

	/**
	 * Finds the most appropriate field to place the cursor for the given horizontal
	 * position.  If the position is between fields, first try to the left and if that
	 * doesn't work, try to the right.
	 */
	int findAppropriateFieldIndex(int x, int y) {
		y -= heightAbove;
		// first check to the left
		for (int i = fields.length - 1; i >= 0; i--) {
			if (fields[i] != null) {
				if (y >= -fields[i].getHeightAbove() && y < fields[i].getHeightBelow() &&
					fields[i].getStartX() <= x) {
					return i;
				}
			}
		}
		// didn't work, check to the right
		for (int i = 0; i < fields.length; i++) {
			if (fields[i] != null) {
				if (y >= -fields[i].getHeightAbove() && y < fields[i].getHeightBelow() &&
					fields[i].getStartX() > x) {
					return i;
				}
			}
		}
		// no matches
		return -1;
	}

	/**
	 * Draws the selection background for individual fields.
	 */
//    private void drawSelection(Graphics g,int startField, int endField) {
//        int start = fields[startField].getStartX();
//        int end = fields[endField].getStartX()+fields[endField].getWidth();
//        int width = end-start;
//        g.fillRect(start,0,width,heightAbove+heightBelow);
//    }

	/**
	 * Draws the selection background for individual fields.
	 */
//    private void drawSelection(Graphics g, int startField, int endField,
//                               int first, int last) {
//        int start = fields[startField].getStartX();
//        int end = fields[endField].getStartX()+fields[endField].getWidth();
//        if (first != -1 && first < start) {
//            start = first;
//        }
//        if (last != -1 && last > end) {
//            end = last;
//        }
//        int width = end-start;
//		g.fillRect(start,0,width,heightAbove+heightBelow);
//    }

	@Override
	public int getPrimaryOffset() {
		return 0;
	}

	boolean isPrimary() {
		return isPrimary;
	}

	@Override
	public Rectangle getFieldBounds(int index) {
		Field f = fields[index];
		Rectangle rect =
			new Rectangle(f.getStartX(), -f.getHeightAbove(), f.getWidth(), f.getHeight());
		rect.y += heightAbove;
		return rect;
	}

	@Override
	public int getIndexSize() {
		return 1;
	}

	@Override
	public int getBeginRowFieldNum(int field1) {
		return 0;
	}

	@Override
	public int getEndRowFieldNum(int field2) {
		return getNumFields();
	}
}
