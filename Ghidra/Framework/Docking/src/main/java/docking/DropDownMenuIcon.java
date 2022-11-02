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
import java.awt.geom.GeneralPath;

import javax.swing.Icon;

/**
 * Icon for a drop down menu button  (triangle pointing down)
 */
public class DropDownMenuIcon implements Icon {
	private static final int ICON_SIZE = 16;

	private Color color;
	private Shape shape;

	/**
	 * Creates a drop down menu icon.
	 * @param color the color of the triangle
	 */
	public DropDownMenuIcon(Color color) {
		this.color = color;
		this.shape = buildShape();
	}

	private Shape buildShape() {

		GeneralPath path = new GeneralPath();

		double iconSize = 16;
		double height = 6;
		double width = 10;
		double leftMargin = (iconSize - width) / 2;
		double topMargin = (iconSize - height) / 2;

		// draw a triangle pointing down; p1 is the bottom; p2 is the left
		double p1x = leftMargin + (width / 2);
		double p1y = topMargin + height;
		double p2x = leftMargin;
		double p2y = topMargin;
		double p3x = leftMargin + width;
		double p3y = topMargin;

		path.moveTo(p1x, p1y);
		path.lineTo(p2x, p2y);
		path.lineTo(p3x, p3y);
		path.lineTo(p1x, p1y);
		path.closePath();

		return path;
	}

	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {

		Graphics2D g2d = (Graphics2D) g;
		g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		try {
			g2d.translate(x, y);
			g2d.setColor(color);
			g2d.fill(shape);
		}
		finally {
			g2d.translate(-x, -y);
		}
	}

	@Override
	public int getIconWidth() {
		return ICON_SIZE;
	}

	@Override
	public int getIconHeight() {
		return ICON_SIZE;
	}

}
