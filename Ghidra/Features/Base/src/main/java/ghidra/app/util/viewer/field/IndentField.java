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
package ghidra.app.util.viewer.field;

import java.awt.*;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.internal.FieldBackgroundColorManager;
import docking.widgets.fieldpanel.internal.PaintContext;
import docking.widgets.fieldpanel.support.*;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.EmptyProxy;
import ghidra.app.util.viewer.proxy.ProxyObj;

/**
 * Field responsible for drawing +/- symbols when over an aggregate datatype that
 * can be opened or closed.  Also adds extra spacing for each level of the sub-datatypes.
 */
public class IndentField implements ListingField {

	private FieldFactory factory;
	private int startX;
	private int startY;
	private int fieldWidth;
	private int height;
	private int heightAbove;
	private ProxyObj proxy;
	private boolean isLast;

	private int indentLevel;
	private int toggleHandleSize;
	private int insetSpace = 1;

	/**
	 * Constructor
	 * @param factory the factory that generated this field.
	 * @param proxy the object associated with this field instance.
	 * @param indentLevel the level of the datatype object.
	 * @param metrics the FontMetrics to used to render the field.
	 * @param x the x position of the field.
	 * @param width the width of the field.
	 * @param isLast true if the object is the last subcomponent at its level.
	 */
	public IndentField(FieldFactory factory, ProxyObj proxy, int indentLevel, FontMetrics metrics,
			int x, int width, boolean isLast) {
		this.factory = factory;
		this.proxy = proxy;
		this.fieldWidth = width;
		this.startX = x;
		this.isLast = isLast;
		this.indentLevel = indentLevel;
		this.heightAbove = metrics.getAscent();
		this.height = metrics.getLeading() + metrics.getAscent() + metrics.getDescent();

		// this class is dependent upon the OpenClosedField in that they work together to perform
		// painting
		toggleHandleSize = OpenCloseField.getOpenCloseHandleSize();
	}

	/**
	 * Returns the FieldFactory that generated this field.
	 */
	@Override
	public FieldFactory getFieldFactory() {
		return factory;
	}

	/**
	 * Returns the FieldModel that contains the FieldFactory that generated this
	 * field.
	 */
	@Override
	public FieldFormatModel getFieldModel() {
		return factory.getFieldModel();
	}

	/**
	 * Returns the object associated with this field instance.
	 */
	@Override
	public ProxyObj getProxy() {
		if (proxy == null) {
			return EmptyProxy.EMPTY_PROXY;
		}
		return proxy;
	}

	/**
	 * Returns the heightAbove the imaginary alignment line used to align fields
	 * on the same row.
	 */
	@Override
	public int getHeightAbove() {
		return heightAbove;
	}

	/**
	 * Returns the heightBelow the imaginary alignment line used to align fields on
	 * the same row.
	 */
	@Override
	public int getHeightBelow() {
		return height - heightAbove;
	}

	/**
	 * Sets the overall y position for this field.
	 * @param yPos the y coordinated of the layout row that it is in.
	 * @param heightAbove the heightAbove the alignment line for the entire layout row.
	 * @param heightBelow the heighBelow the alignment line for the entire layout col.
	 */
	public void setYPos(int yPos, int heightAbove, int heightBelow) {
		this.startY = yPos;
		this.height = heightAbove + heightBelow;
		this.heightAbove = heightAbove;
	}

	/**
	 * Returns the current width of this field.
	 */
	@Override
	public int getWidth() {
		return (indentLevel + 1) * fieldWidth;
	}

	@Override
	public int getPreferredWidth() {
		return getWidth(); // does the width of this field vary?
	}

	/**
	 * Returns the height of this field when populated with the given data.
	 */
	@Override
	public int getHeight() {
		return height;
	}

	/**
	 * Returns the horizontal position of this field.
	 */
	@Override
	public int getStartX() {
		return startX;
	}

	/**
	 * Returns the vertical position of this field.
	 */
	public int getStartY() {
		return startY;
	}

	/**
	 * Sets the starting vertical position of this field.
	 * @param startY the starting vertical position.
	 */
	public void setStartY(int startY) {
		this.startY = startY;
	}

	@Override
	public void paint(JComponent c, Graphics g, PaintContext context,
			Rectangle clip, FieldBackgroundColorManager map, RowColLocation cursorLoc,
			int rowHeight) {
		g.setColor(Color.LIGHT_GRAY);

		// draw the vertical lines to the left of the data (these are shown when there are vertical
		// bars drawn for inset data)
		int fieldTopY = -heightAbove;
		int fieldBottomY = getHeightBelow();
		int toggleHandleHalfLength = toggleHandleSize / 2;
		for (int i = 1; i < indentLevel; i++) {
			int fieldOffset = i * fieldWidth;
			int previousButtonStartX = startX + fieldOffset + insetSpace;
			int midpointX = previousButtonStartX + toggleHandleHalfLength;
			g.drawLine(midpointX, fieldTopY, midpointX, fieldBottomY);
		}

		int toggleHandleStartX = startX + (indentLevel * fieldWidth) + insetSpace;
		int midPointX = toggleHandleStartX + toggleHandleHalfLength;
		int midPointY = fieldTopY / 2;

		// horizontal pointer line (that points from vertical bar to inset data)
		g.drawLine(midPointX, midPointY, startX + (indentLevel + 1) * fieldWidth, midPointY);

		// vertical line above the horizontal pointer line
		g.drawLine(midPointX, fieldTopY, midPointX, midPointY);

		if (!isLast) {
			// vertical line below the horizontal pointer line
			g.drawLine(midPointX, midPointY, midPointX, fieldBottomY);
		}

		paintCursor(g, context.getCursorColor(), cursorLoc);
	}

	private void paintCursor(Graphics g, Color cursorColor, RowColLocation cursorLoc) {
		if (cursorLoc != null) {
			g.setColor(cursorColor);
			Rectangle cursorBounds = getCursorBounds(cursorLoc.row(), cursorLoc.col());
			if (cursorBounds != null) {
				g.fillRect(cursorBounds.x, cursorBounds.y, cursorBounds.width, cursorBounds.height);
			}
		}
	}

	@Override
	public boolean contains(int x, int y) {
		if ((x < startX) || (x >= startX + fieldWidth) || (y < startY) || (y >= startY + height)) {
			return false;
		}
		return true;
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
		return 0;
	}

	@Override
	public int getX(int row, int col) {
		return startX;
	}

	@Override
	public int getY(int row) {
		return startY;
	}

	@Override
	public int getRow(int y) {
		return 0;
	}

	@Override
	public int getCol(int row, int x) {
		return 0;
	}

	@Override
	public boolean isValid(int row, int col) {
		return ((row == 0) && (col == 0));
	}

	@Override
	public Rectangle getCursorBounds(int row, int col) {
		if (!isValid(row, col)) {
			return null;
		}

		return new Rectangle(startX, -heightAbove, 2, height);
	}

	@Override
	public int getScrollableUnitIncrement(int topOfScreen, int direction, int max) {
		if ((topOfScreen < startY) || (topOfScreen > startY + height)) {
			return max;
		}

		if (direction > 0) { // if scrolling down
			return height - (topOfScreen - startY);
		}
		return startY - topOfScreen;
	}

	@Override
	public boolean isPrimary() {
		return false;
	}

	@Override
	public void rowHeightChanged(int newHeightAbove, int newHeightBelow) {
		this.heightAbove = newHeightAbove;
		this.height = newHeightAbove + newHeightBelow;
	}

	@Override
	public String getText() {
		return "";
	}

	@Override
	public String getTextWithLineSeparators() {
		return "";
	}

	@Override
	public RowColLocation textOffsetToScreenLocation(int textOffset) {
		return new DefaultRowColLocation();
	}

	@Override
	public int screenLocationToTextOffset(int row, int col) {
		return 0;
	}

	@Override
	public Object getClickedObject(FieldLocation fieldLocation) {
		return this;
	}
}
