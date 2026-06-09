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
package ghidra.program.model.data;

import java.awt.*;

import javax.swing.Icon;

import generic.theme.GColor;

/**
 * {@link ColorIcon} provides a color icon patch to convey a specified color with 
 * Alpha transparancy.  This implementation was created in support of color 
 * data types (see {@link AbstractColorDataType}).
 */
public class ColorIcon implements Icon {

	private static final int WIDTH = 16;
	private static final int HEIGHT = 16;

	private static Color BORDER_COLOR = new GColor("color.fg");

	private final Color color;

	/**
	 * Construct a 16x16 RGB color icon patch
	 * @param color icon color
	 */
	ColorIcon(Color color) {
		this.color = color;
	}

	@Override
	public int getIconHeight() {
		return HEIGHT;
	}

	@Override
	public int getIconWidth() {
		return WIDTH;
	}

	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {

		Graphics2D g2d = (Graphics2D) g;

		// Enable anti-aliasing
		g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		// Draw a white box with a diagonal black line under the colored-box to convey 
		// Alpha channel transparency while preserving color.
		g.setColor(Color.WHITE);
		g.fillRect(x + 1, y + 1, WIDTH - 2, HEIGHT - 2);
		g.setColor(Color.BLACK);
		g.drawLine(x + 1, y + 1, x + WIDTH - 2, y + HEIGHT - 2);

		// Draw colored-box
		g.setColor(color);
		g.fillRect(x + 1, y + 1, WIDTH - 2, HEIGHT - 2);
		g.setColor(BORDER_COLOR);
		g.drawLine(x + 1, y, x + WIDTH - 2, y);
		g.drawLine(x + WIDTH - 1, y + 1, x + WIDTH - 1, y + HEIGHT - 2);
		g.drawLine(x + 1, y + HEIGHT - 1, x + WIDTH - 2, y + HEIGHT - 1);
		g.drawLine(x, y + 1, x, y + HEIGHT - 2);
	}

	/**
	 * {@return standardized RGB value}
	 */
	public int getRGBValue() {
		return color.getRGB();
	}

}
