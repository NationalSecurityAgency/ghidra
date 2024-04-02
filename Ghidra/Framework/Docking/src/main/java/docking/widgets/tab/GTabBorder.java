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
package docking.widgets.tab;

import java.awt.*;

import javax.swing.border.EmptyBorder;

/**
 * Custom border for the {@link GTab}. For non selected tabs, it basically draws a variation of 
 * a bevel border that is offset from the top by 2 pixels from the selected tab. Selected tabs
 * are drawn at the very top of the component and doesn't draw the bottom border so that it appears
 * to connect to the border of the overall tab panel.
 */
class GTabBorder extends EmptyBorder {
	private static int LEFT_MARGIN = 7;	// 2 for drawn border and 5 pixels for a left margin 
	private static int TOP_MARGIN = 4;	// 2 for border and 2 to play with offset on non-selected
	private static int RIGHT_MARGIN = 2; // 2 for border. Close Icon adds enough of a visual margin
	private static int BOTTOM_MARGIN = 2; // 2 for border
	private int offset = 0;

	private boolean selected;

	GTabBorder(boolean selected) {
		super(TOP_MARGIN, LEFT_MARGIN, BOTTOM_MARGIN, RIGHT_MARGIN);
		this.selected = selected;

		// paint non-selected tabs a bit lower
		if (!selected) {
			offset = 2;
		}
	}

	/**
	 * Paints the border, and also a bottom shadow border that isn't part of the insets, so that
	 * the area that doesn't have tabs, still paints a bottom border
	 */
	@Override
	public void paintBorder(Component c, Graphics g, int x, int y, int w, int h) {
		Color oldColor = g.getColor();
		g.translate(x, y);

		Color innerHighlight = c.getBackground().brighter();
		Color outerHighlight = innerHighlight.brighter();
		Color innerShadow = c.getBackground().darker();
		Color outerShadow = innerShadow.darker();

		// upper
		g.setColor(outerHighlight);
		g.drawLine(1, offset, w - 3, offset); 	// upper outer
		g.setColor(innerHighlight);
		g.drawLine(2, offset + 1, w - 3, offset + 1); 	// upper inner

		// left
		g.setColor(outerShadow);
		g.drawLine(0, offset + 1, 0, h - 1); 		// left outer
		g.setColor(innerHighlight);
		g.drawLine(1, offset + 1, 1, h - 2); 		// left inner

		// right
		g.setColor(innerShadow);
		g.drawLine(w - 2, offset + 1, w - 2, h); // right inner
		g.setColor(outerShadow);
		g.drawLine(w - 1, offset + 1, w - 1, h - 2); // right outer

		if (!selected) {
			g.setColor(outerHighlight);
			g.drawLine(0, h - 1, w - 1, h - 1);	// bottom
		}

		g.translate(-x, -y);
		g.setColor(oldColor);
	}

}
