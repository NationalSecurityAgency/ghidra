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
package resources.icons;

import java.awt.*;

import javax.swing.Icon;

public class ColorIcon implements Icon {
	private final Color color;
	private final Color outlineColor;
	private final int width;
	private final int height;

	public ColorIcon(Color color, Color outlineColor, int size) {
		this(color, outlineColor, size, size);
	}

	public ColorIcon(Color color, Color outlineColor, int width, int height) {
		if (width < 3 || height < 3) {
			throw new IllegalArgumentException("dimension too small");
		}
		this.color = color;
		this.outlineColor = outlineColor;
		this.width = width;
		this.height = height;
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
		Color startColor = g.getColor();
		int h = height;
		int w = width;
		if (outlineColor != null) {
			// 1-pixel 
			g.setColor(outlineColor);
			g.fillRect(x, y, w, h);
			++x;
			++y;
			w -= 2;
			h -= 2;
		}
		g.setColor(color);
		g.fillRect(x, y, w, h);
		g.setColor(startColor);
	}
}
