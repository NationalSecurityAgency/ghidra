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
package help;

import java.awt.*;
import java.awt.geom.*;

import javax.swing.Icon;

/**
 * A basic arrow that points to the right, with padding on the sides and above.
 */
public class HelpRightArrowIcon implements Icon {

	private static final int ICON_SIZE = 20;

	private Color color;
	private Shape shape;

	public HelpRightArrowIcon(Color color) {
		this.color = color;
		this.shape = buildShape();
	}

	private Shape buildShape() {

		GeneralPath barPath = new GeneralPath();

		//
		// Construct the arrow in 2 parts: the line and the angle bracket. The arrow will not fill
		// the full area.  This allows space before and after the arrow.  This space serves as
		// padding between text inside of html content.  The arrow is also closer to the bottom,
		// to aligned vertically with text.
		//
		double height = 10;
		double width = 12;
		double thickness = 2;
		double arrowthickness = 3;

		double top = ICON_SIZE - height;
		double cy = top + (height / 2);
		double p1x = (ICON_SIZE - width) / 2;
		double p1y = cy - (thickness / 2);
		barPath.moveTo(p1x, p1y);

		double barlength = width - 2;
		double p2x = p1x + barlength;
		double p2y = p1y;
		barPath.lineTo(p2x, p2y);

		double p3x = p2x;
		double p3y = p2y + thickness;
		barPath.lineTo(p3x, p3y);

		double p4x = p1x;
		double p4y = p3y;
		barPath.lineTo(p4x, p4y);

		// back to start of arrow line
		barPath.lineTo(p1x, p1y);
		barPath.closePath();

		GeneralPath arrowPath = new GeneralPath();

		// trailing arrow bar center
		p1x = p1x + barlength + arrowthickness;
		p1y = cy;
		arrowPath.moveTo(p1x, p1y);

		// trailing upper arrow bar point
		double trianglewidth = 5;
		p2x = p1x - trianglewidth;
		p2y = top + 1;
		arrowPath.lineTo(p2x, p2y);

		// leading upper arrow bar point
		p3x = p2x - arrowthickness;
		p3y = p2y;
		arrowPath.lineTo(p3x, p3y);

		// leading arrow bar center
		p4x = p1x - arrowthickness;
		p4y = cy;
		arrowPath.lineTo(p4x, p4y);

		// leading lower arrow bar point
		double p5x = p3x;
		double p5y = ICON_SIZE - 1;
		arrowPath.lineTo(p5x, p5y);

		// trailing lower arrow bar point
		double p6x = p2x;
		double p6y = p5y;
		arrowPath.lineTo(p6x, p6y);

		// back to start
		double p7x = p1x;
		double p7y = p1y;
		arrowPath.lineTo(p7x, p7y);
		arrowPath.closePath();

		AffineTransform identity = new AffineTransform();
		Shape barShape = barPath.createTransformedShape(identity);
		Area barArea = new Area(barShape);

		Shape arrowShape = arrowPath.createTransformedShape(identity);
		Area arrowArea = new Area(arrowShape);

		Area fullArea = new Area();
		fullArea.add(barArea);
		fullArea.add(arrowArea);

		return fullArea;
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
