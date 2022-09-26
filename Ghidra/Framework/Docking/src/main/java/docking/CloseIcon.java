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
package docking;

import java.awt.*;

import javax.swing.Icon;

/**
 * Icon for a close button 
 */
public class CloseIcon implements Icon {
	private int size;
	private int margin;
	private Color color;

	/**
	 * Creates a close icon.
	 * @param size the width and height of the icon
	 * @param margin the margin around the "x" 
	 * @param color the color of the "x"
	 */
	public CloseIcon(int size, int margin, Color color) {
		this.size = size;
		this.margin = margin;
		this.color = color;
	}

	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {
		g.setColor(color);
		int xStart = x + margin;
		int yStart = y + margin;
		int xEnd = x + size - margin;
		int yEnd = y + size - margin;
		g.drawLine(xStart, yStart, xEnd, yEnd);
		g.drawLine(xStart, yEnd, xEnd, yStart);
		g.drawLine(xStart + 1, yStart, xEnd + 1, yEnd);
		g.drawLine(xStart + 1, yEnd, xEnd + 1, yStart);
		g.drawLine(xStart - 1, yStart, xEnd - 1, yEnd);
		g.drawLine(xStart - 1, yEnd, xEnd - 1, yStart);
	}

	@Override
	public int getIconWidth() {
		return size;
	}

	@Override
	public int getIconHeight() {
		return size;
	}

}
