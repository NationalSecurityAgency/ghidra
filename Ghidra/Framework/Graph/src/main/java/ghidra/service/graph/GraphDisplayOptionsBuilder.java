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

import java.awt.Color;
import java.util.Objects;

/**
 * Builder for building {@link GraphDisplayOptions}
 */
public class GraphDisplayOptionsBuilder {

	private GraphDisplayOptions displayOptions;

	/**
	 * Create a new GraphDisplayOptionsBuilder
	 * @param graphType the {@link GraphType} of graphs that this instance configures.
	 */
	public GraphDisplayOptionsBuilder(GraphType graphType) {
		displayOptions = new GraphDisplayOptions(graphType);
	}

	/**
	 * Sets the default vertex color for vertexes that don't have a registered vertex type
	 * @param c the default vertex color
	 * @return this GraphDisplayOptionsBuilder
	 */
	public GraphDisplayOptionsBuilder defaultVertexColor(Color c) {
		displayOptions.setDefaultVertexColor(c);
		return this;
	}

	/**
	 * Sets the default edge color for edges that don't have a registered edge type
	 * @param c the default edge color
	 * @return this GraphDisplayOptionsBuilder
	 */
	public GraphDisplayOptionsBuilder defaultEdgeColor(Color c) {
		Objects.requireNonNull(c);
		displayOptions.setDefaultEdgeColor(c);
		return this;
	}

	/**
	 * Sets the vertex selection color
	 * @param color the vertex selection color
	 * @return this GraphDisplayOptionsBuilder
	 */
	public GraphDisplayOptionsBuilder vertexSelectionColor(Color color) {
		displayOptions.setVertexSelectionColor(color);
		return this;
	}

	/**
	 * Sets the edge selection color
	 * @param color the edge selection color
	 * @return this GraphDisplayOptionsBuilder
	 */
	public GraphDisplayOptionsBuilder edgeSelectionColor(Color color) {
		displayOptions.setEdgeSelectionColor(color);
		return this;
	}

	/**
	 * Sets the default vertex shape for vertices that don't have a registered vertex type
	 * @param vertexShape the {@link VertexShape} to use as a default
	 * @return this GraphDisplayOptionsBuilder
	 */
	public GraphDisplayOptionsBuilder defaultVertexShape(VertexShape vertexShape) {
		Objects.requireNonNull(vertexShape);
		displayOptions.setDefaultVertexShape(vertexShape);
		return this;
	}

	/**
	 * Sets the shape and color for vertices of the given type
	 * @param vertexType the vertex type to assign shape and color
	 * @param vertexShape the shape to use for the named vertex type 
	 * @param color the color to use for the named vertex type
	 * @return this GraphDisplayOptionsBuilder
	 */
	public GraphDisplayOptionsBuilder vertex(String vertexType, VertexShape vertexShape,
			Color color) {
		displayOptions.configureVertexType(vertexType, vertexShape, color);
		return this;
	}

	/**
	 * Sets the color for edges of the given type
	 * @param edgeType the edge type to assign color
	 * @param color the color to use for the named edge type
	 * @return this GraphDisplayOptionsBuilder
	 */
	public GraphDisplayOptionsBuilder edge(String edgeType, Color color) {
		displayOptions.configureEdgeType(edgeType, color);
		return this;
	}

	/**
	 * Sets the attribute used to override the color for a vertex
	 * @param colorAttributeKey the attribute key to use for overriding a vertex color
	 * @return this GraphDisplayOptionsBuilder
	 */
	public GraphDisplayOptionsBuilder vertexColorOverrideAttribute(String colorAttributeKey) {
		displayOptions.setVertexColorOverrideAttributeKey(colorAttributeKey);
		return this;
	}

	/**
	 * Sets the attribute used to override the color for a edge
	 * @param colorAttributeKey the attribute key to use for overriding an edge color
	 * @return this GraphDisplayOptionsBuilder
	 */
	public GraphDisplayOptionsBuilder edgeColorOverrideAttribute(String colorAttributeKey) {
		displayOptions.setEdgeColorOverrideAttributeKey(colorAttributeKey);
		return this;
	}

	/**
	 * Sets the attribute used to override the shape for a vertex
	 * @param shapeAttributeKey the attribute key to use of shape override
	 * @return this GraphDisplayOptionsBuilder
	 */
	public GraphDisplayOptionsBuilder shapeOverrideAttribute(String shapeAttributeKey) {
		displayOptions.setVertexShapeOverrideAttributeKey(shapeAttributeKey);
		return this;
	}

	/**
	 * Sets the name of the layout algorithm that will be used to initially layout the graph
	 * @param string the name of the layout algoritm to use to initially layout the graph
	 * @return this GraphDisplayOptionsBuilder
	 */
	public GraphDisplayOptionsBuilder defaultLayoutAlgorithm(String string) {
		displayOptions.setDefaultLayoutAlgorithmName(string);
		return this;
	}

	/**
	 * Sets drawing "mode" for the graph display. If true, vertices are drawn as scaled
	 * cached images with the label inside the shapes. If false, vertices are drawn as smaller
	 * shapes with labels drawn near the shapes. 
	 * @param b true to use pre-rendered icon images
	 * @return this GraphDisplayOptionsBuilder
	 */
	public GraphDisplayOptionsBuilder useIcons(boolean b) {
		displayOptions.setUsesIcons(b);
		return this;
	}

	/**
	 * Sets the length of the arrows to display in the graph. The width will be sized proportionately.
	 * @param length the length the arrows to display in the graph
	 * @return this GraphDisplayOptionsBuilder
	 */
	public GraphDisplayOptionsBuilder arrowLength(int length) {
		displayOptions.setArrowLength(length);
		return this;
	}

	/**
	 * Sets the maximum number of nodes a graph can have and still be displayed.
	 * @param maxNodeCount the maximum number of nodes
	 * @return this GraphDisplayOptionsBuilder
	 */
	public GraphDisplayOptionsBuilder maxNodeCount(int maxNodeCount) {
		displayOptions.getMaxNodeCount();
		return this;
	}

	/**
	 * Sets the vertex label position relative to vertex shape. This is only applicable if the
	 * {@link #useIcons(boolean)} is set to false.
	 * @param labelPosition the relative position to place the vertex label
	 * @return this GraphDisplayOptionsBuilder
	 */
	public GraphDisplayOptionsBuilder labelPosition(GraphLabelPosition labelPosition) {
		displayOptions.setLabelPosition(labelPosition);
		return this;
	}

	/**
	 * Returns a GraphTypeDisplayOptions as configured by this builder
	 * @return  a GraphTypeDisplayOptions as configured by this builder
	 */
	public GraphDisplayOptions build() {
		return displayOptions;
	}

}
