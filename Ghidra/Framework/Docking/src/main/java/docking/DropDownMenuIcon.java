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
 * Icon for a drop down menu button  (triangle pointing down)
 */
public class DropDownMenuIcon implements Icon {
	private int size;
	private int xMargin;
	private int yMargin;
	private Color color;

	/**
	 * Creates a drop down menu icon.
	 * @param size the width and height of the icon
	 * @param xMargin the margin around triangle base
	 * @param yMargin the margin around triangle height
	 * @param color the color of the triangle
	 */
	public DropDownMenuIcon(int size, int xMargin, int yMargin, Color color) {
		this.size = size;
		this.xMargin = xMargin;
		this.yMargin = yMargin;
		this.color = color;
	}

	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {
		g.setColor(color);

		// draw a triangle pointing down
		int p1x = x + size / 2;
		int p1y = y + size - yMargin;
		int p2x = x + xMargin;
		int p2y = y + yMargin;
		int p3x = x + size - xMargin + 1;
		int p3y = y + yMargin;
		int xPoints[] = { p1x, p2x, p3x };
		int yPoints[] = { p1y, p2y, p3y };
		g.fillPolygon(xPoints, yPoints, 3);
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
