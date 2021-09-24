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

import javax.swing.ImageIcon;
import javax.swing.JComponent;

import docking.widgets.fieldpanel.internal.FieldBackgroundColorManager;
import docking.widgets.fieldpanel.internal.PaintContext;
import docking.widgets.fieldpanel.support.*;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.EmptyProxy;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.program.model.listing.Data;
import resources.ResourceManager;

/**
 * FactoryField class for displaying the open/close field.
 */
public class OpenCloseField implements ListingField {
	private static final ImageIcon openImage = ResourceManager.loadImage("images/small_minus.png");
	private static final ImageIcon closedImage = ResourceManager.loadImage("images/small_plus.png");

	private FieldFactory factory;
	private int startX;
	private int startY;
	private int fieldWidth;
	private int heightAbove;
	private int heightBelow;
	private ProxyObj proxy;

	private boolean isOpen;
	private int indentLevel;
	private boolean isLast;

	private int toggleHandleSize;
	private int insetSpace = 1;

	/**
	 * Constructor
	 * @param factory the FieldFactory that created this field.
	 * @param proxy the object associated with this field.
	 * @param indentLevel the indentation level of the data object.
	 * @param metrics the FontMetrics used to render this field.
	 * @param x the starting x position of this field.
	 * @param width the width of this field.
	 * @param isLast true if the data object is the last subcomponent at its level.
	 */
	public OpenCloseField(FieldFactory factory, ProxyObj proxy, int indentLevel,
			FontMetrics metrics, int x, int width, boolean isLast) {
		this.factory = factory;
		this.proxy = proxy;
		this.isOpen = proxy.getListingLayoutModel().isOpen((Data) proxy.getObject());
		this.fieldWidth = width;
		this.startX = x;
		this.indentLevel = indentLevel;
		this.isLast = isLast;
		this.heightAbove = metrics.getAscent();
		this.heightBelow = metrics.getLeading() + metrics.getDescent();
		this.toggleHandleSize = OpenCloseField.getOpenCloseHandleSize();
	}

	@Override
	public FieldFactory getFieldFactory() {
		return factory;
	}

	@Override
	public FieldFormatModel getFieldModel() {
		return factory.getFieldModel();
	}

	@Override
	public ProxyObj getProxy() {
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
	 * @param yPos the starting Ypos of the layout row.
	 * @param heightAbove the heightAbove the alignment line in the layout row.
	 * @param heightBelow the heightBelow the alignment line in the layout row.
	 */
	public void setYPos(int yPos, int heightAbove, int heightBelow) {
		this.startY = yPos;
		this.heightAbove = heightAbove;
		this.heightBelow = heightBelow;
	}

	@Override
	public int getWidth() {
		return (indentLevel + 1) * fieldWidth;
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

		// center in the heightAbove area (negative, since 0 is the baseline of text, which is at
		// the bottom of the heightAbove)
		int toggleHandleStartY = -((heightAbove / 2) + (toggleHandleSize / 2));
		int toggleHandleStartX = startX + (indentLevel * fieldWidth) + insetSpace;

		// TODO: If we're in printing mode, trying to render these open/close images
		//       causes the JVM to bomb. We'd like to eventually figure out why but in
		//       the meantime we can safely comment this out and still generate an acceptable
		//       image.
		//
		if (!context.isPrinting()) {
			if (isOpen) {
				g.drawImage(openImage.getImage(), toggleHandleStartX, toggleHandleStartY,
					context.getBackground(), null);
			}
			else {
				g.drawImage(closedImage.getImage(), toggleHandleStartX, toggleHandleStartY,
					context.getBackground(), null);
			}
		}

		g.setColor(Color.LIGHT_GRAY);

		// draw the vertical lines to the left of the toggle handle (these are shown when
		// there are vertical bars drawn for inset data)
		int fieldTopY = -heightAbove;
		int fieldBottomY = heightBelow;
		int toggleHandleHalfLength = toggleHandleSize / 2;
		for (int i = 1; i < indentLevel; i++) {
			int fieldOffset = i * fieldWidth;
			int previousButtonStartX = startX + fieldOffset + insetSpace;
			int midpointX = previousButtonStartX + toggleHandleHalfLength;
			g.drawLine(midpointX, fieldTopY, midpointX, fieldBottomY);
		}

		if (indentLevel > 0) {
			// horizontal line to the right of the toggle handle
			int indentOffset = getWidth();
			int toggleHandleEndX = toggleHandleStartX + toggleHandleSize;
			int midpointY = toggleHandleStartY + (toggleHandleSize / 2);
			int endX = startX + indentOffset;
			g.drawLine(toggleHandleEndX, midpointY, endX, midpointY);

			// vertical line above toggle handle
			int midpointX = toggleHandleStartX + toggleHandleHalfLength;
			int endY = toggleHandleStartY - insetSpace;
			g.drawLine(midpointX, fieldTopY, midpointX, endY);

			boolean lastAndClosed = isLast && !isOpen;
			if (!lastAndClosed) {
				// extended vertical line below toggle handle
				int buttonBottomY = toggleHandleStartY + toggleHandleSize;
				g.drawLine(midpointX, buttonBottomY, midpointX, fieldBottomY);
			}
		}

		paintCursor(g, context.getCursorColor(), cursorLoc);
	}

	private void paintCursor(Graphics g, Color cursorColor, RowColLocation cursorLoc) {
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
	public void toggleOpenCloseState() {
		proxy.getListingLayoutModel().toggleOpen((Data) proxy.getObject());
	}

//==================================================================================================
// Static Methods
//==================================================================================================

	static int getOpenCloseHandleSize() {
		return openImage.getIconWidth();
	}
}
