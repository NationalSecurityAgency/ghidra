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

import static ghidra.app.util.viewer.field.AbstractOpenCloseField.*;

import java.awt.*;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.internal.FieldBackgroundColorManager;
import docking.widgets.fieldpanel.internal.PaintContext;
import docking.widgets.fieldpanel.support.RowColLocation;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.program.model.listing.Data;

/**
 * FactoryField class for displaying the open/close field.
 */
public class OpenCloseField extends AbstractOpenCloseField {
	private int indentLevel;
	private boolean isLast;
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
	public OpenCloseField(FieldFactory factory, ProxyObj<?> proxy, int indentLevel,
			FontMetrics metrics, int x, int width, boolean isLast) {
		super(factory, proxy, metrics, x, width);
		this.isOpen = proxy.getListingLayoutModel().isOpen((Data) proxy.getObject());
		this.indentLevel = indentLevel;
		this.isLast = isLast;
	}

	@Override
	public int getWidth() {
		return (indentLevel + 1) * fieldWidth;
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
				g.drawImage(OPEN_ICON.getImageIcon().getImage(), toggleHandleStartX,
					toggleHandleStartY, context.getBackground(), null);
			}
			else {
				g.drawImage(CLOSED_ICON.getImageIcon().getImage(), toggleHandleStartX,
					toggleHandleStartY, context.getBackground(), null);
			}
		}

		g.setColor(Palette.LIGHT_GRAY);

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

	/**
	 * Toggles the open state of this field.
	 */
	@Override
	public void toggleOpenCloseState() {
		proxy.getListingLayoutModel().toggleOpen((Data) proxy.getObject());
	}
}
