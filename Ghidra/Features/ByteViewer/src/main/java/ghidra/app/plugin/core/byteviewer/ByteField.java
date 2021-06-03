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
package ghidra.app.plugin.core.byteviewer;

import java.awt.*;
import java.math.BigInteger;

import javax.swing.JComponent;

import docking.util.GraphicsUtils;
import docking.widgets.fieldpanel.field.SimpleTextField;
import docking.widgets.fieldpanel.internal.FieldBackgroundColorManager;
import docking.widgets.fieldpanel.internal.PaintContext;
import docking.widgets.fieldpanel.support.HighlightFactory;
import docking.widgets.fieldpanel.support.RowColLocation;
import ghidra.util.ColorUtils;

/**
 * Fields for the ByteViewer.  This class extends the SimpleTextField to include
 * a fieldOffset which corresponds to the column of the the fieldFactory that
 * generated it.
 */
public class ByteField extends SimpleTextField {
	private int fieldOffset;
	private BigInteger index;
	private int cursorWidth;

	/**
	 * Constructor
	 * @param text the text value to display
	 * @param fontMetrics the font to use to display the text.
	 * @param startX the starting horizontal position of the field.
	 * @param startY the starting vertical position of the field.
	 * @param width the width of the field.
	 * @param allowCursorAtEnd if true, the cursor will be allowed at the end of the field.
	 * @param fieldOffset the column position of the fieldFactory that generated this field.
	 * @param index the field's index
	 * @param hlFactory the factory used to create highlights
	 */
	public ByteField(String text, FontMetrics fontMetrics, int startX, int width,
			boolean allowCursorAtEnd, int fieldOffset, BigInteger index,
			HighlightFactory hlFactory) {

		super(text, fontMetrics, startX, width, allowCursorAtEnd, hlFactory);
		this.fieldOffset = fieldOffset;
		this.index = index;
		this.cursorWidth = fontMetrics.charWidth('W');
	}

	@Override
	public void paint(JComponent c, Graphics g, PaintContext context,
			Rectangle clip, FieldBackgroundColorManager colorManager, RowColLocation cursorLoc, int rowHeight) {
		paintSelection(g, colorManager, 0);
		paintHighlights(g, hlFactory.getHighlights(this, text, -1));
		g.setFont(metrics.getFont());
		if (foregroundColor == null) {
			foregroundColor = context.getForeground();
		}

		g.setColor(foregroundColor);
		GraphicsUtils.drawString(c, g, text, startX, 0);

		Color cursorColor = context.getCursorColor();
		paintCursor(c, g, cursorColor, cursorLoc, context.cursorHidden());
	}

	private void paintCursor(JComponent c, Graphics g, Color cursorColor, RowColLocation cursorLoc,
			boolean cursorHidden) {
		if (cursorLoc == null) {
			return;
		}

		if (cursorLoc.col() >= numCols) {
			return;
		}

		g.setColor(cursorColor);

		int x = startX + metrics.stringWidth(text.substring(0, cursorLoc.col()));
		g.fillRect(x, -heightAbove, cursorWidth, heightAbove + heightBelow);

		if (cursorHidden) {
			return; // no cursor showing; no text to repaint
		}

		// paint the text above the cursor so it is not hidden
		Shape oldClip = g.getClip();
		try {
			g.setClip(x, -heightAbove, cursorWidth, heightAbove + heightBelow);
			Color textColor = ColorUtils.contrastForegroundColor(cursorColor);
			g.setColor(textColor);
			GraphicsUtils.drawString(c, g, text, startX, 0);
		}
		finally {
			g.setClip(oldClip);
		}
	}

	/**
	 * Returns the field offset of the fieldFactory that generated this field.
	 */
	public int getFieldOffset() {
		return fieldOffset;
	}

	public BigInteger getIndex() {
		return index;
	}

	@Override
	public String toString() {
		return getText();
	}
}
