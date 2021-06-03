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
package ghidra.graph.viewer.vertex;

import java.awt.*;
import java.awt.geom.AffineTransform;

import javax.swing.JComponent;

import com.google.common.base.Function;

import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.VisualVertex;

/**
 * The default {@link VisualGraph} renderer.  By default, the shape returned by this class is
 * a {@link Rectangle} of the given vertex's {@link VisualVertex#getComponent() component}.
 * 
 * <p>This class is aware of {@link VertexShapeProvider}s, which allows vertex creators to 
 * provide vertex shapes that differ for rendering and clicking.  See that class for more info.
 *
 * @param <V> the vertex type
 */
public class VisualGraphVertexShapeTransformer<V extends VisualVertex>
		implements Function<V, Shape> {

	/**
	 * Returns the compact shape that the user will see when full, detailed rendering is 
	 * not being performed for a vertex, such as in the satellite viewer or when fully-zoomed-out
	 * 
	 * @param v the vertex 
	 * @return the shape
	 */
	public Shape transformToCompactShape(V v) {
		Shape s = getCompactShape(v);
		return centerShape(s);
	}

	/**
	 * Returns the full (the actual) shape of a vertex.  This can be used to determine if a 
	 * mouse point intersects a vertex or to get the real bounding-box of a vertex.
	 * 
	 * @param v the vertex
	 * @return the shape
	 */
	public Shape transformToFullShape(V v) {
		Shape s = getFullShape(v);
		return centerShape(s);
	}

	@Override
	public Shape apply(V vertex) {
		//
		// This is the default method called by Jung.  We too defer to this for most operations.
		// Clients that need a more attractive shape should call transformToViewableShape().
		//
		Shape s = getFullShape(vertex);
		return centerShape(s);
	}

	private Shape centerShape(Shape s) {
		//
		// Center the vertex by moving it's location up and to the left (without this, the
		// vertex is drawn hanging from it's x,y position).   
		//
		// Note: this is what Jung does for its shapes.  We thought it easier to mimic what
		//       they do rather then have to change all of the edge renderers to compensate.
		// 
		Rectangle bounds = s.getBounds();
		Dimension size = bounds.getSize();
		int halfWidth = -(size.width / 2);
		int halfHeight = -(size.height / 2);

		// subtract any current x/y value to 0-out the new shape
		int x = halfWidth - bounds.x;
		int y = halfHeight - bounds.y;

		AffineTransform xform = AffineTransform.getTranslateInstance(x, y);
		Shape movedShape = xform.createTransformedShape(s);

		return movedShape;
	}

	private Shape getFullShape(V v) {
		if (v instanceof VertexShapeProvider) {
			return ((VertexShapeProvider) v).getFullShape();
		}
		return getDefaultShape(v);
	}

	private Shape getCompactShape(V v) {
		if (v instanceof VertexShapeProvider) {
			return ((VertexShapeProvider) v).getCompactShape();
		}
		return getDefaultShape(v);
	}

	private Shape getDefaultShape(V v) {

		// This used to call vertex.getBounds().   The FGVertex had custom code to make
		// the bounds get the preferred size.  Revisit this code if the size of the vertices 
		// is incorrect.
		JComponent component = v.getComponent();
		return new Rectangle(new Point(0, 0), component.getPreferredSize());
	}
}
