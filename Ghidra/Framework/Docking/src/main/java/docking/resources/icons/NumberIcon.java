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
package docking.resources.icons;

import java.awt.*;
import java.awt.geom.Rectangle2D;

import javax.swing.Icon;
import javax.swing.JComponent;

import docking.util.GraphicsUtils;

/**
 * An icon that paints the given number
 */
public class NumberIcon implements Icon {

	private String number;
	private float bestFontSize = -1;

	public NumberIcon(int number) {
		this.number = Integer.toString(number);
	}

	public void setNumber(int number) {
		this.number = Integer.toString(number);
		bestFontSize = -1;
	}

	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {
		g.setColor(Color.WHITE);
		g.fillRect(x, y, getIconWidth(), getIconHeight());
		g.setColor(new Color(0xb5d5ff));
		g.drawRect(x, y, getIconWidth(), getIconHeight());

		float fontSize = getMaxFontSize(g, getIconWidth() - 1, getIconHeight());
		Font originalFont = g.getFont();
		Font textFont = originalFont.deriveFont(fontSize).deriveFont(Font.BOLD);
		g.setFont(textFont);

		FontMetrics fontMetrics = g.getFontMetrics(textFont);
		Rectangle2D stringBounds = fontMetrics.getStringBounds(number, g);
		int textHeight = (int) stringBounds.getHeight();
		int iconHeight = getIconHeight();
		int space = y + iconHeight - textHeight;
		int halfSpace = space >> 1;
		int baselineY = y + iconHeight - halfSpace;// - halfTextHeight;// + halfTextHeight;

		int textWidth = (int) stringBounds.getWidth();
		int iconWidth = getIconWidth();
		int halfWidth = iconWidth >> 1;
		int halfTextWidth = textWidth >> 1;
		int baselineX = x + (halfWidth - halfTextWidth);

		g.setColor(Color.BLACK);
		JComponent jc = null;
		if (c instanceof JComponent) {
			jc = (JComponent) c;
		}
		GraphicsUtils.drawString(jc, g, number, baselineX, baselineY);
	}

	private float getMaxFontSize(Graphics g, int width, int height) {
		if (bestFontSize > 0) {
			return bestFontSize;
		}

		float size = 12f;
		Font font = g.getFont().deriveFont(size); // reasonable default
		if (textFitsInFont(g, font, width, height)) {
			bestFontSize = size;
			return bestFontSize;
		}

		do {
			size--;
			font = g.getFont().deriveFont(size);
		}
		while (!textFitsInFont(g, font, width, height));

		bestFontSize = Math.max(1f, size);
		return bestFontSize;
	}

	private boolean textFitsInFont(Graphics g, Font font, int width, int height) {

		// padding so the text does not touch the border
		int padding = 2;
		FontMetrics fontMetrics = g.getFontMetrics(font);
		int textWidth = fontMetrics.stringWidth(number) + padding;
		if (textWidth > width) {
			return false;
		}

		int textHeight = fontMetrics.getHeight();
		return textHeight < height;
	}

	@Override
	public int getIconHeight() {
		return 16;
	}

	@Override
	public int getIconWidth() {
		return 16;
	}
}
