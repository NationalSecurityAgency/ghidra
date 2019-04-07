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
package docking.widgets.fieldpanel;

import java.awt.Graphics;
import java.awt.Rectangle;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.internal.LayoutBackgroundColorManager;
import docking.widgets.fieldpanel.internal.PaintContext;
import docking.widgets.fieldpanel.support.FieldLocation;

/**
 * Interface for a set of data fields that represent one indexable set of information
 * in the model. The fields in a layout are arranged into rows.  The height of the
 * row is the height of the tallest field in that row.  Each field contains one or
 * more lines of text.
 */
public interface Layout {

	/**
	 * Returns the total height of this layout.
	 */
	int getHeight();

	/**
	 * Returns the vertical offset (in pixels) of the start of the primary
	 * field in the layout.
	 * 
	 * @return -1 if layout does not have a primary field.
	 */
	int getPrimaryOffset();

	/**
	 * Inserts empty space above the layout
	 * @param size the amount of space to insert above the layout
	 */
	public void insertSpaceAbove(int size);

	/**
	 * Inserts empty space below the layout
	 * @param size the amount of space to insert below the layout
	 */
	public void insertSpaceBelow(int size);

	/**
	 * Returns the number of Fields in this Layout.
	 */
	int getNumFields();

	/**
	 * Returns the i'th Field in this Layout.
	 * @param index the index of the field to retrieve.
	 */
	Field getField(int index);

	/**
	 * Paints this layout on the screen.
	 *
	 * @param g The graphics context with which to paint.
	 * @param context contains various information needed to do the paint 
	 * @param rect the screen area that needs to be painted.
	 * @param layoutColorMap indicates where the selection exists
	 * @param cursorLocation the location of the cursor or null if the cursor is not in this layout
	 */
	void paint(JComponent c, Graphics g, PaintContext context, Rectangle rect,
			LayoutBackgroundColorManager layoutColorMap, FieldLocation cursorLocation);

	/**
	 * Sets the cursor to the given point location.  The cursor will be positioned
	 * to the row column position that is closest to the given point.
	 * @param cursorLoc the location that is to be filled in.
	 * @param x the x coordinate of the point to be translated into a cursor location.
	 * @param y the y coordinate of the point to be translated into a cursor location. 
	 * @return the x coordinated of the computed cursor location.
	 */
	int setCursor(FieldLocation cursorLoc, int x, int y);

	/**
	 * Returns a rectangle which bounds the given cursor position.
	 * @param fieldNum the index of the field containing the cursor position.
	 * @param row the the text row in the field containing the cursor position.
	 * @param col the character position in the row containing the cursor position.
	 */
	Rectangle getCursorRect(int fieldNum, int row, int col);

	/**
	 * Moves the cursor up one row from its current position.
	 * @param cursorLoc the cursor location object to be modified
	 * @param lastX the x coordinate of the cursor before the move.
	 * @return true if the cursor was successfully moved up without leaving the layout.
	 */
	boolean cursorUp(FieldLocation cursorLoc, int lastX);

	/**
	 * Moves the cursor up down row from its current position.
	 * @param cursorLoc the cursor location object to be modified
	 * @param lastX the x coordinate of the cursor before the move.
	 * @return true if the cursor was successfully moved down without leaving the layout.
	 */
	boolean cursorDown(FieldLocation cursorLoc, int lastX);

	/**
	 * Sets the given FieldLocation as far to the left as possible.
	 * @param cursorLoc the cursor location object to be modified.
	 * @return the x coordinate of the cursor after the operation.
	 */
	int cursorBeginning(FieldLocation cursorLoc);

	/**
	 * Sets the given FieldLocation as far to the right as possible.
	 * @param cursorLoc the cursor location object to be modified.
	 * @return the x coordinate of the cursor after the operation.
	 */
	int cursorEnd(FieldLocation cursorLoc);

	/**
	 * Sets the given FieldLocation one position to the left.  If already at the
	 * left most position, it tries to move to the end of the previous row.
	 * @param cursorLoc the cursor location object to be modified.
	 * @return the x coordinate of the cursor after the operation.  Returns -1 if
	 * it was already at the top, left most position.
	 */
	int cursorLeft(FieldLocation cursorLoc);

	/**
	 * Sets the given FieldLocation one position to the right.  If already at the
	 * right most position, it tries to move to the beginning of the next row.
	 * @param cursorLoc the cursor location object to be modified.
	 * @return the x coordinate of the cursor after the operation.  Returns -1 if
	 * it was already at the bottom, right most position.
	 */
	int cursorRight(FieldLocation cursorLoc);

	/**
	 * Tries to move the cursor into this layout.
	 * @param cursorLoc the field location to hold new location.
	 * @param lastX the last valid x coordinate.
	 * @param fromTop true if entering from the above this layout
	 * @return true if the cursor successfully moves into this layout.
	 */
	boolean enterLayout(FieldLocation cursorLoc, int lastX, boolean fromTop);

	/**
	 * Returns the amount to scroll to reveal the line of text.
	 * @param topOfScreen the y coordinate that represents the top or bottom of
	 * the screen
	 * @param direction the direction to scroll
	 */
	int getScrollableUnitIncrement(int topOfScreen, int direction);

	/**
	 * Returns true if the the given yPos lies within this layout.
	 * @param yPos the vertical coordinate to check if in this layout.
	 */
	boolean contains(int yPos);

	/**
	 * Returns the bounds of the given field (in coordinates relative to the layout)
	 * @param index the field id for the field for which to get bounds
	 */
	Rectangle getFieldBounds(int index);

	/**
	 * Returns the number of indexes consumed by this layout.
	 */
	int getIndexSize();

	int getBeginRowFieldNum(int field1);

	int getEndRowFieldNum(int field2);

	/**
	 * Returns the smallest possible width of this layout that can display its full contents
	 * @return the smallest possible width of this layout that can display its full contents
	 */
	int getCompressableWidth();
}
