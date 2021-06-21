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
package ghidra.graph.visualization;

import static org.jungrapht.visualization.layout.util.PropertyLoader.*;

import java.awt.*;
import java.util.Map;

import org.apache.commons.text.StringEscapeUtils;
import org.jungrapht.visualization.util.ShapeFactory;

import com.google.common.base.Splitter;

import ghidra.service.graph.Attributed;
import ghidra.service.graph.AttributedEdge;

/**
 * a container for various functions used by ProgramGraph
 */
abstract class ProgramGraphFunctions {
	static float edgeWidth = Float.parseFloat(System.getProperty(PREFIX + "edgeWidth", "4.0f"));

	// cannot instantiate nor extend
	private ProgramGraphFunctions() {
	}

	/**
	 * a default implementation of a {@link ShapeFactory} to supply shapes for attributed vertices and edges
	 */
	private static ShapeFactory<Attributed> shapeFactory = new ShapeFactory<>(n -> 50, n -> 1.0f);

	/**
	 * return various 'Shapes' based on an attribute name
	 *
	 * @param n the attributed key (a vertex or edge)
	 * @param name the attribute name
	 * @return a Shape for the passed 'n' with attribute 'name'
	 */
	private static Shape byShapeName(Attributed n, String name) {
		if (name == null) {
			return null;
		}
		switch (name) {
			case "Square":
				return shapeFactory.getRectangle(n);
			case "Circle":
				return shapeFactory.getEllipse(n);
			case "Triangle":
				return shapeFactory.getRegularPolygon(n, 3);
			case "TriangleDown":
				return shapeFactory.getRegularPolygon(n, 3, Math.PI);
			case "Diamond":
				return shapeFactory.getRectangle(n, Math.PI / 4);
			case "Star":
				return shapeFactory.getRegularStar(n, 5);
			case "Pentagon":
				return shapeFactory.getRegularPolygon(n, 5);
			case "Hexagon":
				return shapeFactory.getRegularPolygon(n, 6);
			case "Octagon":
				return shapeFactory.getRegularPolygon(n, 8);
			default:
				return null;
		}
	}

	/*
	 * Gets the Shape object to use when drawing this vertex. If "Icon" attribute
	 * is set it will use that, otherwise "VertexType" to will translate a code flow
	 * name to a shape
	 *
	 * @param vertex the Attributed object to get a shape for
	 * @return a Shape object to use when displaying the object
	 */
	public static Shape getVertexShape(Attributed vertex) {
		Shape shape = byShapeName(vertex, vertex.getAttribute("Icon"));
		if (shape != null) {
			return shape;
		}
		String vertexType = vertex.getAttribute("VertexType");
		if (vertexType == null) {
			return shapeFactory.getRectangle(vertex);
		}
		switch (vertexType) {
			case "Entry":
				return shapeFactory.getRegularPolygon(vertex, 3, Math.PI);
			case "Exit":
				return shapeFactory.getRegularPolygon(vertex, 3);
			case "Switch":
				return shapeFactory.getRectangle(vertex, Math.PI / 4);
			case "Body":
			case "External":
				return shapeFactory.getRectangle(vertex);
			default:
				return shapeFactory.getEllipse(vertex);
		}
	}

	/**
	 * Provides a {@link Stroke} (line width and style) for an attributed edge
	 * @param edge the edge to get a stroke value
	 * @return the stroke for the edge
	 */
	public static Stroke getEdgeStroke(AttributedEdge edge) {
		String edgeType = edge.getAttribute("EdgeType");
		if (edgeType != null && edgeType.equals("Fall-Through")) {
			return new BasicStroke(edgeWidth * 2);
		}
		return new BasicStroke(edgeWidth);
	}

	/**
	 * gets a display label from an {@link Attributed} object (vertex)
	 * @param attributed the attributed object to get a label for
	 * @param preferredLabelAttribute the attribute to use for the label, if available
	 * @return the label for the given {@link Attributed}
	 */
	public static String getLabel(Attributed attributed, String preferredLabelAttribute) {
		Map<String, String> map = attributed.getAttributeMap();
		String name = StringEscapeUtils.escapeHtml4(map.get("Name"));
		if (map.containsKey(preferredLabelAttribute)) {
			name = StringEscapeUtils.escapeHtml4(map.get(preferredLabelAttribute));
		}
		return "<html>" + String.join("<p>", Splitter.on('\n').split(name));
	}
}
