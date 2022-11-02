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
 * Icon for a close button 
 */
public class CloseIcon implements Icon {
	private int size;
	private Color color;
	private Shape shape;

	/**
	* Creates a close icon.
	* @param isSmall false signals to use a 16x16 size; true signals to use an 8x8 size
	* @param color the color of the "x"
	*/
	public CloseIcon(boolean isSmall, Color color) {
		this.size = isSmall ? 8 : 16;
		this.color = color;
		this.shape = buildShape();
	}

	private Shape buildShape() {
		GeneralPath path = new GeneralPath();

		/*
		 	We use trial and error sizing.   This class allows clients to specify the icon size. At
		 	the time of writing, there were only 2 sizes in use: 16 and 8 pixels.   If more size
		 	needs arise, we can revisit how the values below are chosen.
		 */

		double margin = 2;
		double shapeSize = 11;
		double thickness = 1.7;
		if (size == 8) {
			margin = 0;
			shapeSize = 7;
			thickness = 1;
		}

		double p1x = margin;
		double p1y = margin + thickness;
		double p2x = margin + thickness;
		double p2y = margin;
		double p3x = margin + shapeSize;
		double p3y = margin + shapeSize - thickness;
		double p4x = margin + shapeSize - thickness;
		double p4y = margin + shapeSize;

		path.moveTo(p1x, p1y);
		path.lineTo(p2x, p2y);
		path.lineTo(p3x, p3y);
		path.lineTo(p4x, p4y);
		path.lineTo(p1x, p1y);

		p1x = margin + shapeSize - thickness;
		p1y = margin;
		p2x = margin + shapeSize;
		p2y = margin + thickness;
		p3x = margin + thickness;
		p3y = margin + shapeSize;
		p4x = margin;
		p4y = margin + shapeSize - thickness;

		path.moveTo(p1x, p1y);
		path.lineTo(p2x, p2y);
		path.lineTo(p3x, p3y);
		path.lineTo(p4x, p4y);
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
		return size;
	}

	@Override
	public int getIconHeight() {
		return size;
	}

}
