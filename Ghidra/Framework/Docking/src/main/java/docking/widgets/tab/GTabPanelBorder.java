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
 * Custom border for the {@link GTab}.
 */
public class GTabPanelBorder extends EmptyBorder {
	public static final int MARGIN_SIZE = 2;
	public static final int BOTTOM_SOLID_COLOR_SIZE = 3;

	public GTabPanelBorder() {
		super(0, 0, BOTTOM_SOLID_COLOR_SIZE, 0);
	}

	/**
	 * Paints the border, and also a bottom shadow border that isn't part of the insets, so that
	 * the area that doesn't have tabs, still paints a bottom border
	 */
	@Override
	public void paintBorder(Component c, Graphics g, int x, int y, int w, int h) {
		Insets insets = getBorderInsets(c);
		Color oldColor = g.getColor();
		g.translate(x, y);

		Color highlight = GTab.TAB_BG_COLOR.brighter().brighter();

		g.setColor(GTab.SELECTED_TAB_BG_COLOR);
		g.fillRect(insets.left, h - insets.bottom, w - insets.right - 1, insets.bottom);

		g.setColor(highlight);
		g.drawLine(insets.left, h - insets.bottom - 1, w - insets.right - 1, h - insets.bottom - 1);

		g.translate(-x, -y);
		g.setColor(oldColor);
	}

}
