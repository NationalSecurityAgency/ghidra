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
package ghidra.graph.viewer.edge;

import java.awt.Shape;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.visualization.RenderContext;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;

/**
 * A renderer designed to override default edge rendering to NOT paint emphasizing effects.  We
 * do this because space is limited in the satellite and because this rendering can take excess
 * processing time.
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class VisualGraphEdgeSatelliteRenderer<V extends VisualVertex, E extends VisualEdge<V>>
		extends VisualEdgeRenderer<V, E> {

	private final VisualEdgeRenderer<V, E> rendererDelegate;

	public VisualGraphEdgeSatelliteRenderer(VisualEdgeRenderer<V, E> delegate) {
		this.rendererDelegate = delegate;
	}

	@Override
	protected boolean isInHoveredVertexPath(E e) {
		return false;
	}

	@Override
	protected boolean isInFocusedVertexPath(E e) {
		return false;
	}

	@Override
	protected boolean isSelected(E e) {
		return false;
	}

	@Override
	protected boolean isEmphasiszed(E e) {
		return false;
	}

	@Override
	public Shape getEdgeShape(RenderContext<V, E> rc, Graph<V, E> graph, E e, float x1, float y1,
			float x2, float y2, boolean isLoop, Shape vertexShape) {
		return rendererDelegate.getEdgeShape(rc, graph, e, x1, y1, x2, y2, isLoop, vertexShape);
	}

	@Override
	protected Shape getVertexShapeForArrow(RenderContext<V, E> rc, Layout<V, E> layout, V v) {
		// we use the default shape (the full shape) for arrow detection
		return getCompactShape(rc, layout, v);
	}
}
