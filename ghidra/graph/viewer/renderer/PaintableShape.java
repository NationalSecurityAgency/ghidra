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
import java.util.Objects;

/**
 * A base class for shapes that can be painted on the graph.  See {@link MouseDebugPaintable}.
 */
public class PaintableShape {

	protected Shape shape;
	protected Color color = new Color(255, 200, 0, 127);  // orange with alpha;
	protected Stroke stroke;

	protected double tx;
	protected double ty;

	protected boolean shapeFinished = false;

	// Note: tx,ty together comprise the offset of the LAYOUT layer, or the amount the view
	//       has been dragged.
	protected PaintableShape(double tx, double ty) {
		// for subclasses
		this.tx = tx;
		this.ty = ty;
	}

	public PaintableShape(Shape s) {
		this.shape = Objects.requireNonNull(s);
	}

	public PaintableShape(Shape s, Color c) {
		this.shape = Objects.requireNonNull(s);
		this.color = Objects.requireNonNull(c);
	}

	public PaintableShape(Shape s, Color c, Stroke stroke) {
		this.shape = Objects.requireNonNull(s);
		this.color = Objects.requireNonNull(c);
		this.stroke = Objects.requireNonNull(stroke);
	}

	public double getTx() {
		return tx;
	}

	public double getTy() {
		return ty;
	}

	public Shape getShape() {
		return shape;
	}

	public Color getColor() {
		return color;
	}

	public Stroke getStroke() {
		return stroke;
	}

	public void shapeFinished() {
		// for subclasses that have shapes that change on-the-fly
		this.shapeFinished = true;
	}

	public boolean isShapeFinished() {
		return shapeFinished;
	}

	public void paint(Graphics2D g) {
		g.setColor(color);
		if (stroke != null) {
			g.setStroke(stroke);
		}
		g.fill(shape);
	}
}
