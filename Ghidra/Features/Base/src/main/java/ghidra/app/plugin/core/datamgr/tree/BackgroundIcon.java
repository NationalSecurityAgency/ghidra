/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.datamgr.tree;

import java.awt.*;

import javax.swing.Icon;

class BackgroundIcon implements Icon {

	private static Color VERSION_ICON_COLOR_DARK = new Color(0x82, 0x82, 0xff);
	private static Color VERSION_ICON_COLOR_LIGHT = new Color(0x9f, 0x9f, 0xff);

	private static final int WIDTH = 18;
	private static final int HEIGHT = 17;

	private int width;
	private int height;
	private boolean isVersioned;

	BackgroundIcon(boolean isVersioned) {
		this(WIDTH, HEIGHT, isVersioned);
	}

	BackgroundIcon(int width, int height, boolean isVersioned) {
		this.width = width;
		this.height = height;
		this.isVersioned = isVersioned;
	}

	public int getIconHeight() {
		return height;
	}

	public int getIconWidth() {
		return width;
	}

	public void paintIcon(Component c, Graphics g, int x, int y) {
		if (isVersioned) {
			g.setColor(VERSION_ICON_COLOR_LIGHT);
			g.fillRect(x + 1, y + 1, width - 2, height - 2);
			g.setColor(VERSION_ICON_COLOR_DARK);
			g.drawLine(x + 1, y, x + width - 2, y);
			g.drawLine(x + width - 1, y + 1, x + width - 1, y + height - 2);
			g.drawLine(x + 1, y + height - 1, x + width - 2, y + height - 1);
			g.drawLine(x, y + 1, x, y + height - 2);
		}
		else {
			g.setColor(c.getBackground());
			g.fillRect(x, y, width, height);

		}
	}
}
