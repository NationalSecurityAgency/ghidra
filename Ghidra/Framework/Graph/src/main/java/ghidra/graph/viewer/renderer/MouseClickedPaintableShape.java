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
package ghidra.graph.viewer.renderer;

import java.awt.Color;
import java.awt.Point;
import java.awt.geom.Ellipse2D;

/**
 * A debugging shape painter that allows the user to see where a mouse clicked happened.
 */
public class MouseClickedPaintableShape extends PaintableShape {

	private static final Color DEFAULT_COLOR = new Color(255, 200, 0, 127); // orangish

	public MouseClickedPaintableShape(Point p, double tx, double ty) {
		this(p, tx, ty, DEFAULT_COLOR);
	}

	public MouseClickedPaintableShape(Point p, double tx, double ty, Color color) {
		super(tx, ty);
		this.color = color;

		int x = p.x;
		int y = p.y;
		int radius = 15;
		int half = radius >> 1;
		x = x - half;
		y = y - half;
		Ellipse2D circle = new Ellipse2D.Double(x, y, radius, radius);
		this.shape = circle;

		shapeFinished = true;
	}
}
