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

import docking.widgets.fieldpanel.support.*;
import generic.theme.GIcon;
import ghidra.app.util.viewer.proxy.EmptyProxy;
import ghidra.app.util.viewer.proxy.ProxyObj;

/**
 * FactoryField class for displaying the open/close field.
 */
public abstract class AbstractOpenCloseField implements ListingField {
	protected static final GIcon OPEN_ICON =
		new GIcon("icon.base.util.viewer.fieldfactory.openclose.open");
	protected static final GIcon CLOSED_ICON =
		new GIcon("icon.base.util.viewer.fieldfactory.openclose.closed");

	private FieldFactory factory;
	protected int startX;
	protected int startY;
	protected int fieldWidth;
	protected int heightAbove;
	protected int heightBelow;
	protected ProxyObj<?> proxy;

	protected boolean isOpen;

	protected int toggleHandleSize;

	/**
	 * Constructor
	 * @param factory the FieldFactory that created this field.
	 * @param proxy the object associated with this field.
	 * @param metrics the FontMetrics used to render this field.
	 * @param x the starting x position of this field.
	 * @param width the width of this field.
	 */
	public AbstractOpenCloseField(FieldFactory factory, ProxyObj<?> proxy,
			FontMetrics metrics, int x, int width) {
		this.factory = factory;
		this.proxy = proxy;
		this.fieldWidth = width;
		this.startX = x;

		this.heightAbove = metrics.getAscent();
		this.heightBelow = metrics.getLeading() + metrics.getDescent();
		this.toggleHandleSize = AbstractOpenCloseField.getOpenCloseHandleSize();
	}

	@Override
	public FieldFactory getFieldFactory() {
		return factory;
	}

	@Override
	public ProxyObj<?> getProxy() {
		if (proxy == null) {
			return EmptyProxy.EMPTY_PROXY;
		}
		return proxy;
	}

	@Override
	public int getHeightAbove() {
		return heightAbove;
	}

	@Override
	public int getHeightBelow() {
		return heightBelow;
	}

	/**
	 * Sets the yPos relative to the overall layout.
	 * @param yPos the starting Y position of the layout row.
	 * @param heightAbove the heightAbove the alignment line in the layout row.
	 * @param heightBelow the heightBelow the alignment line in the layout row.
	 */
	public void setYPos(int yPos, int heightAbove, int heightBelow) {
		this.startY = yPos;
		this.heightAbove = heightAbove;
		this.heightBelow = heightBelow;
	}

	@Override
	public int getPreferredWidth() {
		return getWidth(); // does the width of this field vary?
	}

	@Override
	public int getHeight() {
		return heightAbove + heightBelow;
	}

	@Override
	public int getStartX() {
		return startX;
	}

	/**
	 * Returns the vertical position of this field.
	 * @return the position
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

	protected void paintCursor(Graphics g, Color cursorColor, RowColLocation cursorLoc) {
		if (cursorLoc != null) {
			g.setColor(cursorColor);
			Rectangle cursorBounds = getCursorBounds(cursorLoc.row(), cursorLoc.col());
			g.fillRect(cursorBounds.x, cursorBounds.y, cursorBounds.width, cursorBounds.height);
		}
	}

	@Override
	public boolean contains(int x, int y) {
		if ((x < startX) || (x >= startX + fieldWidth) || (y < startY) ||
			(y >= startY + heightAbove + heightBelow)) {
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

		return new Rectangle(startX, -heightAbove, 2, heightAbove + heightBelow);
	}

	@Override
	public int getScrollableUnitIncrement(int topOfScreen, int direction, int max) {
		if ((topOfScreen < startY) || (topOfScreen > startY + heightAbove + heightBelow)) {
			return max;
		}

		if (direction > 0) { // if scrolling down
			return heightAbove + heightBelow - (topOfScreen - startY);
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
		this.heightBelow = newHeightBelow;
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

	/**
	 * Toggles the open state of this field.
	 */
	public abstract void toggleOpenCloseState();

//==================================================================================================
// Static Methods
//==================================================================================================

	static int getOpenCloseHandleSize() {
		return OPEN_ICON.getIconWidth();
	}
}
