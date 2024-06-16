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
package ghidra.app.plugin.core.datamgr.tree;

import java.awt.*;

import javax.swing.Icon;

import generic.theme.GColor;
import generic.theme.GThemeDefaults.Colors.Palette;

/**
 * An icon used by the data types tree to uniformly space all icons.  Clients of versioned objects
 * can signal that this icon can paint a custom background.
 */
public class DtBackgroundIcon implements Icon {

	private static Color VERSION_ICON_COLOR = new GColor("color.bg.icon.versioned");

	private static Color ALPHA = Palette.NO_COLOR;

	private Color bgColor = Palette.NO_COLOR;

	private int width = 24;
	private int height = 16;

	DtBackgroundIcon() {
		this(false);
	}

	DtBackgroundIcon(boolean isVersioned) {
		this.bgColor = isVersioned ? VERSION_ICON_COLOR : ALPHA;
	}

	@Override
	public int getIconHeight() {
		return height;
	}

	@Override
	public int getIconWidth() {
		return width;
	}

	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {
		g.setColor(bgColor);
		g.fillRect(x + 1, y + 1, width - 2, height - 2);
		g.drawLine(x + 1, y, x + width - 2, y);
		g.drawLine(x + width - 1, y + 1, x + width - 1, y + height - 2);
		g.drawLine(x + 1, y + height - 1, x + width - 2, y + height - 1);
		g.drawLine(x, y + 1, x, y + height - 2);
	}
}
