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
import java.awt.geom.Rectangle2D;

public class MouseDraggedPaintableShape extends PaintableShape {

	private static final Color START_COLOR = new Color(200, 0, 80, 25);
	private static final Color END_COLOR = new Color(200, 0, 80, 200);

	private Paint paint;

	public MouseDraggedPaintableShape(Point start, Point end, double tx, double ty) {
		super(tx, ty);
		this.color = new Color(200, 0, 80, 147);
		this.stroke = new BasicStroke(15);

		int x1 = start.x;
		int y1 = start.y;
		int x2 = end.x;
		int y2 = end.y;

		int w = Math.abs(x2 - x1);
		int h = Math.abs(y2 - y1);

		if (w == 0) {
			x2 += 1;
		}
		if (h == 0) {
			y2 += 1;
		}

		Rectangle2D rect = new Rectangle2D.Double(x1, y1, w, h);
		rect.setFrameFromDiagonal(x1, y1, x2, y2);
		rebuildPaint(start, end);
		this.shape = rect;
	}

	public void setPoints(Point start, Point end) {

		int x1 = start.x;
		int y1 = start.y;
		int x2 = end.x;
		int y2 = end.y;

		int w = Math.abs(x2 - x1);
		int h = Math.abs(y2 - y1);
		if (w == 0) {
			x2 += 1;
		}
		if (h == 0) {
			y2 += 1;
		}

		Rectangle2D rect = (Rectangle2D) shape;
		rect.setFrameFromDiagonal(x1, y1, x2, y2);
		rebuildPaint(start, end);
	}

	private void rebuildPaint(Point start, Point end) {
		paint = new GradientPaint(start.x, start.y, START_COLOR, end.x, end.y, END_COLOR, true);
	}

	@Override
	public void paint(Graphics2D g) {
		g.setPaint(paint);
		g.setStroke(stroke);
		g.fill(shape);
	}
}
