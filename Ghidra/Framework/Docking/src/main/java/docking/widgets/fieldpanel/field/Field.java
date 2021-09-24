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

import java.awt.Graphics;
import java.awt.Rectangle;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.internal.FieldBackgroundColorManager;
import docking.widgets.fieldpanel.internal.PaintContext;
import docking.widgets.fieldpanel.support.RowColLocation;

/**
 * Interface for display fields used by the FieldPanel
 */
public interface Field {

	/**
	 * Returns the current width of this field
	 * @return the current width of this field
	 */
	public int getWidth();

	/**
	 * The minimum required width to paint the contents of this field
	 * @return the minimum required width to paint the contents of this field
	 */
	public int getPreferredWidth();

	/**
	 * Returns the height of this field when populated with the given data
	 * @return the height
	 */
	public int getHeight();

	/**
	 * Returns the height above the baseLine
	 * @return the height above
	 */
	public int getHeightAbove();

	/**
	 * Returns the height below the baseLine
	 * @return the height below
	 */
	public int getHeightBelow();

	/**
	 * Returns the horizontal position of this field
	 * @return the position
	 */
	public int getStartX();

	/**
	 * Paints this field
	 * @param c the component to paint onto
	 * @param g the graphics context
	 * @param context common paint parameters
	 * @param clip the clipping region to paint into
	 * @param colorManager contains background color information for the field
	 * @param cursorLoc the row,column cursor location within the field or null if the field does
	 * not contain the cursor
	 * @param rowHeight the number of pixels in each row of text in the field
	 */
	public void paint(JComponent c, Graphics g, PaintContext context, Rectangle clip,
			FieldBackgroundColorManager colorManager, RowColLocation cursorLoc, int rowHeight);

	/**
	 * Returns true if the given point is in this field
	 * @param x the horizontal coordinate of the point
	 * @param y the relative y position in this layout
	 * @return true if the given point is in this field
	 */
	public boolean contains(int x, int y);

	/**
	 * Returns the number of data model rows represented by this field.  Some fields may change
	 * the row count by wrapping or truncating.  The value returned here will be the original data
	 * row count before any transformations were applied.
	 * @return the number of data rows
	 */
	public int getNumDataRows();

	/**
	 * Returns the number of rows in this field
	 * @return the number of rows in this field
	 */
	public int getNumRows();

	/**
	 * Returns the number of columns in the given row
	 * @param row the row from which to get the number of columns; this is the screen row
	 * @return the number of columns
	 */
	public int getNumCols(int row);

	/**
	 * Returns the x coordinate for the given cursor position
	 * @param row the text row of interest
	 * @param col the character column
	 * @return the x value
	 */
	public int getX(int row, int col);

	/**
	 * Returns the y coordinate for the given row
	 * @param row the text row of interest
	 * @return the y value
	 */
	public int getY(int row);

	/**
	 * Returns the row containing the given y coordinate
	 * @param y vertical pixel coordinate relative to the top of the screen
	 * @return the row
	 */
	public int getRow(int y);

	/**
	 * Returns the cursor column position for the given x coordinate on the given row
	 * @param row the text row to find the column on
	 * @param x the horizontal pixel coordinate for which to find the character position
	 * @return the column
	 */
	public int getCol(int row, int x);

	/**
	 * Returns true if the given row and column represent a valid location for this field with
	 * the given data
	 * @param row the text row
	 * @param col the character position
	 * @return tru if valid
	 */
	public boolean isValid(int row, int col);

	/**
	 * Returns a bounding rectangle for the cursor at the given position
	 * @param row the text row
	 * @param col the character position
	 * @return the rectangle
	 */
	public Rectangle getCursorBounds(int row, int col);

	/**
	 * Returns the amount to scroll to the next or previous line
	 * @param topOfScreen the current y position of the top of the screen
	 * @param direction the direction of the scroll (1 down, -1 up)
	 * @param max the maximum amount to scroll for the entire row - will be positive for down, and
	 * 		negative for up)
	 * @return the scroll amount
	 */
	public int getScrollableUnitIncrement(int topOfScreen, int direction, int max);

	/**
	 * Returns true if this field is "primary" (the most important) field;  used to determine the
	 * "primary" line in the layout
	 * @return true if this field is "primary"
	 */
	public boolean isPrimary();

	/**
	 * notifies field that the rowHeight changed
	 * @param heightAbove the height above the baseline
	 * @param heightBelow the height below the baseline
	 */
	public void rowHeightChanged(int heightAbove, int heightBelow);

	/**
	 * Returns a string containing all the text in the field
	 * @return the string
	 */
	public String getText();

	/**
	 * Returns a string containing all the text in the field with extra newlines
	 * @return a string containing all the text in the field with extra newlines
	 */
	public String getTextWithLineSeparators();

	/**
	 * Returns the row, column position  for an offset into the string returned by getText()
	 * @param textOffset the offset into the entire text string for this field
	 * @return a RowColLocation that contains the row,column location in the field for a position in
	 * 		the overall field text
	 */
	public RowColLocation textOffsetToScreenLocation(int textOffset);

	/**
	 * Returns the text offset in the overall field text string for the given row and column
	 * @param row the row
	 * @param col the column
	 * @return the offset
	 */
	public int screenLocationToTextOffset(int row, int col);
}
