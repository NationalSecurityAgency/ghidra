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
package datagraph.graph.explore;

import java.awt.Shape;
import java.awt.geom.AffineTransform;

import com.google.common.base.Function;

import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.visualization.RenderContext;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.edge.VisualEdgeRenderer;

/**
 * Edge renderer for {@link AbstractExplorationGraph}s. Using information from the vertices to
 * vertically align incoming and outgoing edges with the corresponding inner pieces in the
 * vertex's display component.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class EgEdgeRenderer<V extends EgVertex, E extends VisualEdge<V>>
		extends VisualEdgeRenderer<V, E> {

	@Override
	public Shape getEdgeShape(RenderContext<V, E> rc, Graph<V, E> graph, E e, float x1, float y1,
			float x2, float y2, boolean isLoop, Shape vertexShape) {
		Function<? super E, Shape> edgeXform = rc.getEdgeShapeTransformer();
		Shape shape = edgeXform.apply(e);
		AffineTransform xform = AffineTransform.getTranslateInstance(x1, y1);

		// apply the transformations; converting the given shape from model space into graph space
		return xform.createTransformedShape(shape);
	}
}
