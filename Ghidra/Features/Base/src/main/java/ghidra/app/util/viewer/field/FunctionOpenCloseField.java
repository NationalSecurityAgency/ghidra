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
import docking.widgets.fieldpanel.support.RowColLocation;
import ghidra.app.util.viewer.proxy.FunctionProxy;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.program.model.address.Address;

/**
 * Field class for displaying the open/close field widget for function variables.
 */
public class FunctionOpenCloseField extends AbstractOpenCloseField {

	/**
	 * Constructor
	 * @param factory the FieldFactory that created this field.
	 * @param proxy the object associated with this field.
	 * @param metrics the FontMetrics used to render this field.
	 * @param x the starting x position of this field.
	 * @param width the width of this field.
	 */
	public FunctionOpenCloseField(FieldFactory factory, ProxyObj<?> proxy,
			FontMetrics metrics, int x, int width) {
		super(factory, proxy, metrics, x, width);
		if (proxy instanceof FunctionProxy functionProxy) {
			Address functionAddress = functionProxy.getFunctionAddress();
			this.isOpen = proxy.getListingLayoutModel().isFunctionOpen(functionAddress);
		}
	}

	@Override
	public int getWidth() {
		return fieldWidth;
	}

	@Override
	public void paint(JComponent c, Graphics g, PaintContext context,
			Rectangle clip, FieldBackgroundColorManager map, RowColLocation cursorLoc,
			int rowHeight) {

		// center in the heightAbove area (negative, since 0 is the baseline of text, which is at
		// the bottom of the heightAbove)
		int toggleHandleStartY = -((heightAbove / 2) + (toggleHandleSize / 2));
		int toggleHandleStartX = startX;

		//  If we're in printing mode, trying to render these open/close images
		//  causes the JVM to bomb. We'd like to eventually figure out why but in
		//  the meantime we can safely comment this out and still generate an acceptable
		//  image.
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
		paintCursor(g, context.getCursorColor(), cursorLoc);
	}

	/**
	 * Toggles the open state of this field.
	 */
	@Override
	public void toggleOpenCloseState() {
		if (proxy instanceof FunctionProxy functionProxy) {
			Address functionAddress = functionProxy.getFunctionAddress();
			proxy.getListingLayoutModel().setFunctionOpen(functionAddress, !isOpen);
		}
	}
}
