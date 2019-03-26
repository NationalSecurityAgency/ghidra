/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import javax.swing.JComponent;

import docking.widgets.fieldpanel.internal.FieldBackgroundColorManager;
import docking.widgets.fieldpanel.internal.PaintContext;
import docking.widgets.fieldpanel.support.RowColLocation;

/**
 * A Text field that is blank.
 */

public class EmptyTextField implements Field {

	protected int startX;
	protected int width;
	protected int heightAbove;
	protected int height;
	protected boolean isPrimary;

	/**
	 * Constructs a new EmptyTextField
	 * @param heightAbove the height above the baseline of the text field.
	 * @param heightBelow the height below the baseline of the text field.
	 * @param startX the starting x coordinate.
	 * @param width the width of the field.
	 * the end of the text.
	 */
	public EmptyTextField(int heightAbove, int heightBelow, int startX, int width) {

		this.startX = startX;
		this.width = width;
		this.height = heightAbove + heightBelow;
		this.heightAbove = heightAbove;
	}

	/**
	 * Returns true if the cursor is allowed past the last character.  This
	 * field always returns false since there is no text.
	 */
	public boolean isAllowCursorAtEnd() {
		return false;
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
		return 0;
	}

	/**
	 * 
	 * @see docking.widgets.fieldpanel.field.Field#getHeight()
	 */
	@Override
	public int getHeight() {
		return height;
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
		return 0;
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
		return 0;
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
		return 0;
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
		if (col != 0) {
			return false;
		}
		return true;
	}

	/**
	 * @see docking.widgets.fieldpanel.field.Field#paint(java.awt.Graphics, docking.widgets.fieldpanel.internal.PaintContext, boolean, docking.widgets.fieldpanel.support.RowColLocation)
	 */
	@Override
	public void paint(JComponent c, Graphics g, PaintContext context,
			FieldBackgroundColorManager map, RowColLocation cursorLoc, int rowHeight) {
		paintCursor(g, context.getCursorColor(), cursorLoc);
	}

	private void paintCursor(Graphics g, Color cursorColor, RowColLocation cursorLoc) {

		if (cursorLoc != null) {
			g.setColor(cursorColor);
			if (cursorLoc.col() == 0) {
				int x = startX;
				g.fillRect(x, -heightAbove, 2, height);
			}
		}
	}

	/**
	 * 
	 * @see docking.widgets.fieldpanel.field.Field#getCursorBounds(int, int)
	 */
	@Override
	public Rectangle getCursorBounds(int row, int col) {
		if (row != 0) {
			return null;
		}
		int x = startX;
		return new Rectangle(x, -heightAbove, 2, height);
	}

	/**
	 * 
	 * @see docking.widgets.fieldpanel.field.Field#contains(int, int)
	 */
	@Override
	public boolean contains(int x, int y) {
		if ((x >= startX) && (x < startX + width) && (y >= -heightAbove) &&
			(y < height - heightAbove)) {
			return true;
		}
		return false;
	}

	/**
	 * Sets the foreground color which isn't used by objects of this class
	 * @param color the new foreground color.
	 */
	public void setForeground(Color color) {
	}

	/**
	 * Get the foreground color.
	 *
	 * @return Color could return null if the setForeground() method was
	 * not called, and if this method is called before the paint() method
	 * was called.
	 */
	public Color getForeground() {
		return Color.WHITE;
	}

	/**
	 * 
	 * @see docking.widgets.fieldpanel.field.Field#getScrollableUnitIncrement(int, int, int)
	 */
	@Override
	public int getScrollableUnitIncrement(int topOfScreen, int direction, int max) {
		if ((topOfScreen < -heightAbove) || (topOfScreen > height - heightAbove)) {
			return max;
		}

		if (direction > 0) { // if scrolling down
			return height - topOfScreen - heightAbove;
		}
		return heightAbove - topOfScreen;
	}

	/**
	 * @see docking.widgets.fieldpanel.field.Field#isPrimary()
	 */
	@Override
	public boolean isPrimary() {
		return isPrimary;
	}

	/**
	 * Sets the primary state for this field
	 * @param state the state to set the primary property.
	 */
	public void setPrimary(boolean state) {
		isPrimary = state;
	}

	/**
	 * @see docking.widgets.fieldpanel.field.Field#getHeightAbove()
	 */
	@Override
	public int getHeightAbove() {
		return heightAbove;
	}

	/**
	 * @see docking.widgets.fieldpanel.field.Field#getHeightBelow()
	 */
	@Override
	public int getHeightBelow() {
		return height - heightAbove;
	}

	/**
	 * @see docking.widgets.fieldpanel.field.Field#rowHeightChanged(int, int)
	 */
	@Override
	public void rowHeightChanged(int newHeightAbove, int newHeightBelow) {
		// don't care

	}

	/**
	 * @see docking.widgets.fieldpanel.field.Field#getText()
	 */
	@Override
	public String getText() {
		return "";
	}

	@Override
	public String getTextWithLineSeparators() {
		return "";
	}

	/**
	 * @see docking.widgets.fieldpanel.field.Field#textOffsetToScreenLocation(int)
	 */
	@Override
	public RowColLocation textOffsetToScreenLocation(int textOffset) {
		return new RowColLocation(0, 0);
	}

	/**
	 * @see docking.widgets.fieldpanel.field.Field#screenLocationToTextOffset(int, int)
	 */
	@Override
	public int screenLocationToTextOffset(int row, int col) {
		return 0;
	}
}
