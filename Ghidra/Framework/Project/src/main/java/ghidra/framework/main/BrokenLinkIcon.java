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
package ghidra.framework.main;

import java.awt.*;

import javax.swing.Icon;

/**
 * Icon class for for altering a baseIcon to render as a "broken" link-file icon.
 */
public class BrokenLinkIcon implements Icon {

	private Icon baseIcon;

	/**
	 * Constructs a "broken" link-file icon.
	 * @param baseIcon the base icon that will always be drawn first.
	 */
	public BrokenLinkIcon(Icon baseIcon) {
		this.baseIcon = baseIcon;
	}

	@Override
	public int getIconHeight() {
		return baseIcon.getIconHeight();
	}

	@Override
	public int getIconWidth() {
		return baseIcon.getIconWidth();
	}

	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {
		baseIcon.paintIcon(c, g, x, y);

		Graphics2D g2d = (Graphics2D) g;

		// Enable anti-aliasing
		g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		g.setColor(Color.red);

		int h = getIconHeight();
		int halfh = h / 2;
		int w = getIconWidth();
		int halfw = w / 2;
		// 
		g.drawLine(x, y + halfh - 1, x + halfw + 1, y + halfh - 3);
		g.drawLine(x + halfw + 1, y + halfh - 3, x + halfw - 1, y + halfh + 1);
		g.drawLine(x + halfw - 1, y + halfh + 1, x + w - 1, y + halfh - 1);
	}
}
