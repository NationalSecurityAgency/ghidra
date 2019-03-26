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

import java.awt.*;
import java.awt.geom.GeneralPath;
import java.util.ArrayList;
import java.util.List;

public class MouseDraggedLinePaintableShape extends PaintableShape {

	private List<Point> points = new ArrayList<>();
	private List<Point> controls = new ArrayList<>();

	public MouseDraggedLinePaintableShape(Point start, Point end, double tx, double ty) {
		super(tx, ty);
		this.color = new Color(0, 200, 0, 137);
		this.stroke = new BasicStroke(20);

		points.add(start);
		points.add(end);
		buildShape();
	}

	public void addPoint(Point p) {
		points.add(p);
		buildShape();
	}

	private void buildShape() {
		controls.clear();

		Point start = points.get(0);
		Point p1 = start;
		Point p2 = points.get(1);

		GeneralPath path = new GeneralPath();
		path.moveTo(p1.x, p1.y);
		if (points.size() == 2) {
			path.lineTo(p2.x, p2.y);
			path.closePath();
			this.shape = path;
			return;
		}

		boolean useControl = true;
		for (int i = 2; i < points.size(); i++) {

			Point p3 = points.get(i);

			if (useControl) {
				path.quadTo(p2.x, p2.y, p3.x, p3.y);
			}
			else {
				path.lineTo(p3.x, p3.y);
			}

			useControl = !useControl;

			p1 = p2;
			p2 = p3;
		}

		for (int i = points.size() - 1; i >= 0; i--) {
			Point p = points.get(i);
			path.moveTo(p.x, p.y);
		}

		path.closePath();
		this.shape = path;
	}

	@Override
	public void paint(Graphics2D g) {
		g.setColor(color);
		g.draw(shape);
//			g.fill(shape);

//			g.setColor(new Color(20, 200, 20, 147));
//			controls.forEach(c -> {
		//
//				int x = c.x;
//				int y = c.y;
//				int size = 10;
//				x -= size >> 1;
//				y -= size >> 1;
//				Rectangle2D r = new Rectangle2D.Double(x, y, size, size);
//				g.fill(r);
//			});
		//
//			g.setColor(Color.pink);
//			points.forEach(p -> {
//				int x = p.x;
//				int y = p.y;
//				int size = 6;
//				x -= size >> 1;
//				y -= size >> 1;
//				Rectangle2D r = new Rectangle2D.Double(x, y, size, size);
//				g.fill(r);
//			});
	}

}
