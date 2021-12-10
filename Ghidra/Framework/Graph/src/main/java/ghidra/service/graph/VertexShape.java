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
package ghidra.service.graph;

import java.awt.Rectangle;
import java.awt.Shape;
import java.awt.geom.*;
import java.util.*;

/**
 * Class for defining shapes to use for rendering vertices in a graph
 */
public abstract class VertexShape {
	private static Map<String, VertexShape> registeredShapes = new HashMap<>();
	private static int SIZE = 50;

	public static VertexShape RECTANGLE = new RectangleVertexShape(SIZE);
	public static VertexShape ELLIPSE = new EllipseVertexShape(SIZE);
	public static VertexShape TRIANGLE_UP = new TriangleUpVertexShape(SIZE);
	public static VertexShape TRIANGLE_DOWN = new TriangleDownVertexShape(SIZE);
	public static VertexShape STAR = new StarVertexShape(SIZE);
	public static VertexShape DIAMOND = new DiamondVertexShape(SIZE);
	public static VertexShape PENTAGON = new PentagonVertexShape(SIZE);
	public static VertexShape HEXAGON = new HexagonVertexShape(SIZE);
	public static VertexShape OCTAGON = new OctagonVertexShape(SIZE);

	private Shape cachedShape;
	private String name;
	private int size;

	VertexShape(String name, int size) {
		this.name = name;
		this.size = size;
		registeredShapes.put(name, this);
	}

	/**
	 * Returns the name of the shape
	 * @return the name of the shape
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the {@link Shape} for this {@link VertexShape} instance
	 * @return the {@link Shape} for this {@link VertexShape} instance
	 */
	public Shape getShape() {
		if (cachedShape == null) {
			cachedShape = size(createShape());
		}
		return cachedShape;
	}

	private Shape size(Shape shape) {
		AffineTransform transform = new AffineTransform();
		Rectangle bounds = shape.getBounds();
		double scale = size / bounds.getWidth();
		transform.scale(scale, scale);
		return transform.createTransformedShape(shape);
	}

	/**
	 * Gets the relative amount of margin space to allocate above the label. The default is
	 * 0.5 which will center the label in the associated shape. A value closer to 0 will move
	 * the label closer to the top and a value closer to 1 will move the label closer to the 
	 * bottom.
	 * @return the relative amount of margin space to allocate obove the label.s
	 */
	public double getLabelPosition() {
		return .5;
	}

	/**
	 * Returns the size factor for a shape relative to its label. Shapes are sized based on the
	 * label of a vertex so that the label can fit inside the shape (mostly). Some subclasses
	 * will need to override this value to some value > 1 to fit the label in the shape. For 
	 * example, a rectangle shape does not need to be extended because text naturally fits. But
	 * for a shape like a triangle, its bounding box needs to be bigger so that text doesn't
	 * "stick out" in the narrow part of the triangle. 
	 * @return the size factor for a shape relatvie to its label
	 */
	public double getShapeToLabelRatio() {
		return 1.0;
	}

	/**
	 * This is a factor to keep some shapes from being so distorted by very long labels that they
	 * effectively lose their shape when seen by the user
	 * @return the max width to height ratio
	 */
	public int getMaxWidthToHeightRatio() {
		return 10;
	}

	protected abstract Shape createShape();

	/**
	 * Returns the {@link VertexShape} for the given shape name
	 * @param shapeName the name of the shape for which to get the {@link VertexShape}
	 * @return the {@link VertexShape} for the given shape name
	 */
	public static VertexShape getShape(String shapeName) {
		return registeredShapes.get(shapeName);
	}

	/**
	 * Returns a list of names for all the supported {@link VertexShape}s
	 * @return a list of names for all the supported {@link VertexShape}s
	 */
	public static List<String> getShapeNames() {
		ArrayList<String> list = new ArrayList<String>(registeredShapes.keySet());
		Collections.sort(list);
		return list;
	}

	@Override
	public int hashCode() {
		return Objects.hash(name, size);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		VertexShape other = (VertexShape) obj;
		return Objects.equals(name, other.name) && size == other.size;
	}

//////////////////////////////////////////////////////////////////////////////////////////////////
//Vertex Shape Classes
//////////////////////////////////////////////////////////////////////////////////////////////////
	static class RectangleVertexShape extends VertexShape {
		private RectangleVertexShape(int size) {
			super("Rectangle", size);
		}

		protected Shape createShape() {
			return new Rectangle2D.Double(-1.0, -1.0, 2.0, 2.0);
		}
	}

	static class EllipseVertexShape extends VertexShape {

		private EllipseVertexShape(int size) {
			super("Ellipse", size);
		}

		protected Shape createShape() {
			return new Ellipse2D.Double(-1.0, -1.0, 2.0, 2.0);
		}

		@Override
		public double getShapeToLabelRatio() {
			return 1.4;
		}
	}

	static class TriangleUpVertexShape extends VertexShape {

		private TriangleUpVertexShape(int size) {
			super("Triangle Up", size);
		}

		protected Shape createShape() {
			Path2D path = new Path2D.Double();
			path.moveTo(-1.0, 1.0);
			path.lineTo(1.0, 1.0);
			path.lineTo(0.0, -1.0);
			path.closePath();
			return path;
		}

		@Override
		public double getShapeToLabelRatio() {
			return 1.6;
		}

		@Override
		public double getLabelPosition() {
			return 0.90;
		}
	}

	static class TriangleDownVertexShape extends VertexShape {
		private TriangleDownVertexShape(int size) {
			super("Triangle Down", size);
		}

		protected Shape createShape() {
			Path2D path = new Path2D.Double();
			path.moveTo(-1.0, -1.0);
			path.lineTo(1.0, -1.0);
			path.lineTo(0.0, 1.0);
			path.closePath();
			return path;
		}

		@Override
		public double getShapeToLabelRatio() {
			return 1.6;
		}

		@Override
		public double getLabelPosition() {
			return 0.10;
		}
	}

	static class StarVertexShape extends VertexShape {

		private StarVertexShape(int size) {
			super("Star", size);
		}

		protected Shape createShape() {
			int numPoints = 7;
			Path2D path = new Path2D.Double();
			double outerRadius = 2;
			double innerRadius = 1;
			double deltaAngle = Math.PI / numPoints;
			double angle = 3 * Math.PI / 2;		// start such that star points up.
			path.moveTo(outerRadius * Math.cos(angle), outerRadius * Math.sin(angle));
			for (int i = 0; i < numPoints; i++) {
				angle += deltaAngle;
				path.lineTo(innerRadius * Math.cos(angle), innerRadius * Math.sin(angle));
				angle += deltaAngle;
				path.lineTo(outerRadius * Math.cos(angle), outerRadius * Math.sin(angle));
			}
			return path;
		}

		@Override
		public double getShapeToLabelRatio() {
			return 2.0;
		}

	}

	static class DiamondVertexShape extends VertexShape {
		private DiamondVertexShape(int size) {
			super("Diamond", size);
		}

		protected Shape createShape() {
			Path2D path = new Path2D.Double();
			path.moveTo(0.0, -1.0);
			path.lineTo(-1.0, 0.0);
			path.lineTo(0.0, 1.0);
			path.lineTo(1.0, 0.0);
			path.closePath();
			return path;
		}

		@Override
		public double getShapeToLabelRatio() {
			return 1.6;
		}
	}

	static class EquilateralPolygonVertexShape extends VertexShape {
		private int numSides;
		private double startAngle;

		protected EquilateralPolygonVertexShape(String name, int numSides, double startAngle,
				int size) {
			super(name, size);
			this.numSides = numSides;
			this.startAngle = startAngle;
		}

		protected Shape createShape() {
			Path2D path = new Path2D.Double();

			double deltaAngle = Math.PI * 2 / numSides;
			double angle = startAngle;

			path.moveTo(Math.cos(angle), Math.sin(angle));
			for (int i = 0; i < numSides; i++) {
				angle += deltaAngle;
				path.lineTo(Math.cos(angle), Math.sin(angle));
			}
			return path;
		}

		@Override
		public int getMaxWidthToHeightRatio() {
			return 2;
		}

		@Override
		public double getShapeToLabelRatio() {
			return 1.4;
		}
	}

	static class PentagonVertexShape extends EquilateralPolygonVertexShape {

		private PentagonVertexShape(int size) {
			super("Pentaon", 5, Math.PI + Math.PI / 10, size);
		}
	}

	static class HexagonVertexShape extends EquilateralPolygonVertexShape {

		private HexagonVertexShape(int size) {
			super("Hexagon", 6, 0, size);
		}
	}

	static class OctagonVertexShape extends EquilateralPolygonVertexShape {

		private OctagonVertexShape(int size) {
			super("Octagon", 8, 0, size);
		}
	}
}
