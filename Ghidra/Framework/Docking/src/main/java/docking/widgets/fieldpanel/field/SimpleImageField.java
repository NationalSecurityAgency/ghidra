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

import javax.swing.ImageIcon;
import javax.swing.JComponent;

import docking.widgets.fieldpanel.internal.FieldBackgroundColorManager;
import docking.widgets.fieldpanel.internal.PaintContext;
import docking.widgets.fieldpanel.support.RowColLocation;

/**
 * Field to display an image.
 */
public class SimpleImageField implements Field {

	protected ImageIcon icon;
	protected FontMetrics metrics;
	protected int startX;
	protected int width;
	protected int height;
	protected boolean center;
	protected boolean isPrimary;
	protected int heightAbove;

	/**
	 * Constructs a new field for displaying an image.
	 * @param icon the image icon to display
	 * @param metrics the font metrics
	 * @param startX the starting x coordinate of the field.
	 * @param startY the starting y coordinate of the field.
	 * @param width the width of the field.
	 */
	public SimpleImageField(ImageIcon icon, FontMetrics metrics, int startX, int startY, int width) {
		this(icon, metrics, startX, startY, width, false);
	}

	/**
	 * Constructs a new field for displaying an image.
	 * @param icon the image icon to display
	 * @param metrics the font metrics
	 * @param startX the starting x coordinate of the field.
	 * @param startY the starting y coordinate of the field.
	 * @param width the width of the field.
	 * @param center flag to center the image in the field.
	 */
	public SimpleImageField(ImageIcon icon, FontMetrics metrics, int startX, int startY, int width,
			boolean center) {

		this.heightAbove = metrics.getMaxAscent() + metrics.getLeading();
		this.height = heightAbove + metrics.getMaxDescent();

		this.icon = icon;
		this.metrics = metrics;
		this.startX = startX;
		this.width = width;
		this.center = center;

		// The height is initially set to the font height.
		// If the font height is less than the icon height and the provided width
		// is the less than the icon width, then scale the height relative to the
		// width. Otherwise, use the icon height.
		//
		if (icon != null) {
			if (this.height < icon.getIconHeight()) {
				if (this.width < icon.getIconWidth()) {
					this.height = (width * icon.getIconHeight()) / icon.getIconWidth();
				}
				else {
					this.height = icon.getIconHeight();
				}
			}
		}
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
	 * 
	 * @see docking.widgets.fieldpanel.field.Field#getCol(int, int)
	 */
	@Override
	public int getCol(int row, int x) {
		return 0;
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
		return new Rectangle(startX, -heightAbove, width, height);
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
		return 1;
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
		return -heightAbove - topOfScreen;
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
	 * @see docking.widgets.fieldpanel.field.Field#getWidth()
	 */
	@Override
	public int getWidth() {
		return width;
	}

	@Override
	public int getPreferredWidth() {
		return icon.getIconWidth();
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
	 * @see docking.widgets.fieldpanel.field.Field#getY(int)
	 */
	@Override
	public int getY(int row) {
		return -heightAbove;
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
		if (icon == null) {
			return;
		}

		int tmpWidth = icon.getIconWidth();
		int tmpHeight = icon.getIconHeight();
		int xoffset = 0;
		int yoffset = 0;

		// if we are centering the image, then compute the offsets
		//
		if (center) {
			if (width > icon.getIconWidth()) {
				xoffset = width / 2 - icon.getIconWidth() / 2;
			}
			if (height > icon.getIconHeight()) {
				yoffset = height / 2 - icon.getIconHeight() / 2;
			}
		}

		// check to make sure that we are not going to draw outside the
		// max rectagle
		//
		if (tmpWidth > width) {
			tmpWidth = width;
		}
		if (tmpHeight > height) {
			tmpHeight = height;
		}

		// draw the image, scaling to fit inside specified rectangle
		//
		g.drawImage(icon.getImage(), startX + xoffset, -heightAbove + yoffset, tmpWidth, tmpHeight,
			icon.getImageObserver());

		if (cursorLoc != null) {
			g.setColor(context.getCursorColor());
			Rectangle rect = getCursorBounds(cursorLoc.row(), cursorLoc.col());
			g.drawRect(rect.x, rect.y, tmpWidth - 1, tmpHeight - 1);
		}
	}

	/**
	 * 
	 * @see docking.widgets.fieldpanel.field.Field#isPrimary()
	 */
	@Override
	public boolean isPrimary() {
		return isPrimary;
	}

	/**
	 * Sets the primary state of this field
	 * @param state true if this field is primary, false otherwise.
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
