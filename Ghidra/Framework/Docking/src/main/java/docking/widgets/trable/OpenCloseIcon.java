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
package docking.widgets.trable;

import java.awt.*;

import javax.swing.Icon;

import generic.theme.GThemeDefaults.Colors;

/**
 * Icon used for the expand/collapse control in a {@link GTrable}
 */
public class OpenCloseIcon implements Icon {
	private int width;
	private int height;
	private int[] xPoints;
	private int[] yPoints;
	private Color color = Colors.FOREGROUND;

	/**
	 * Constructor
	 * @param isOpen if true, draws an icon that indicates the row is open, otherwise draws an
	 * icon that the icon indicates the row is closed
	 * @param width the width to draw the icon
	 * @param height the height to draw the icon
	 */
	public OpenCloseIcon(boolean isOpen, int width, int height) {
		this.width = width;
		this.height = height;
		if (isOpen) {
			buildDownPointingTriangle();
		}
		else {
			buildRightPointingTriangle();
		}
	}

	public void setColor(Color color) {
		this.color = color;
	}

	private void buildDownPointingTriangle() {
		int triangleWidth = 8;
		int triangleHeight = 4;

		int startX = width / 2 - triangleWidth / 2;
		int endX = startX + triangleWidth;

		int startY = height / 2 - triangleHeight / 2;
		int endY = startY + triangleHeight;

		xPoints = new int[] { startX, endX, (startX + endX) / 2 };
		yPoints = new int[] { startY, startY, endY };

	}

	private void buildRightPointingTriangle() {
		int triangleWidth = 4;
		int triangleHeight = 8;

		int startX = width / 2 - triangleWidth / 2;
		int endX = startX + triangleWidth;

		int startY = height / 2 - triangleHeight / 2;
		int endY = startY + triangleHeight;

		xPoints = new int[] { startX, endX, startX };
		yPoints = new int[] { startY, (startY + endY) / 2, endY };
	}

	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {
		g.setColor(color);
		g.translate(x, y);
		Graphics2D graphics2D = (Graphics2D) g;
		graphics2D.drawPolygon(xPoints, yPoints, 3);
		graphics2D.fillPolygon(xPoints, yPoints, 3);
		g.translate(-x, -y);
	}

	@Override
	public int getIconWidth() {
		return width;
	}

	@Override
	public int getIconHeight() {
		return height;
	}

}
