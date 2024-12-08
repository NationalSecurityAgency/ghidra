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

import java.util.*;

import com.google.common.base.Function;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.visualization.RenderContext;
import edu.uci.ics.jung.visualization.renderers.Renderer;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.edge.BasicEdgeLabelRenderer;

/**
 * This was created to add the ability to paint selected vertices above other vertices.  We need
 * this since the Jung Graph has no notion of Z-order and thus does not let us specify that any
 * particular vertex should be above another one.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class VisualGraphRenderer<V extends VisualVertex, E extends VisualEdge<V>>
		extends edu.uci.ics.jung.visualization.renderers.BasicRenderer<V, E> {

	private static GridPainter gridPainter;

	/**
	 * Sets a painter to show an underlying grid. (To see a layout's associated grid, search
	 * for calls to this method and un-comment them)
	 * @param gridPainter A painter that paints the grid that a layout was based on.
	 */
	public static void setGridPainter(GridPainter gridPainter) {
		VisualGraphRenderer.gridPainter = gridPainter;
	}

	private Renderer.EdgeLabel<V, E> edgeLabelRenderer = new BasicEdgeLabelRenderer<>();

	public VisualGraphRenderer(Renderer.EdgeLabel<V, E> edgeLabelRenderer) {
		this.edgeLabelRenderer = edgeLabelRenderer;
	}

	@Override
	public void render(RenderContext<V, E> renderContext, Layout<V, E> layout) {
		try {
			mimickSuperPaintingWithoutPaintingSelectedVertices(renderContext, layout);
		}
		catch (Exception e) {
			if (e instanceof ConcurrentModificationException) {
				// let it pass; this can happen if we mutate the graph in the background while
				// the view is painting
				return;
			}

			throw e;
		}
	}

	private void mimickSuperPaintingWithoutPaintingSelectedVertices(
			RenderContext<V, E> renderContext, Layout<V, E> layout) {

		if (gridPainter != null) {
			gridPainter.paintLayoutGridCells(renderContext, layout);
		}
		for (E e : layout.getGraph().getEdges()) {

			renderEdge(renderContext, layout, e);
			renderEdgeLabel(renderContext, layout, e);
		}

		Collection<V> defaultVertices = layout.getGraph().getVertices();
		List<V> vertices = GraphViewerUtils.createCollectionWithZOrderBySelection(defaultVertices);

		for (V v : vertices) {
			renderVertex(renderContext, layout, v);
			renderVertexLabel(renderContext, layout, v);
		}

		// paint all the edges
		// DEBUG code to show the edges *over* the vertices
//		for (E e : layout.getGraph().getEdges()) {
//			renderEdge(renderContext, layout, e);
//			renderEdgeLabel(renderContext, layout, e);
//		}

	}

	@Override
	public void renderVertexLabel(RenderContext<V, E> rc, Layout<V, E> layout, V v) {

		String label = rc.getVertexLabelTransformer().apply(v);
		if (label == null) {
			return;
		}

		super.renderVertexLabel(rc, layout, v);
	}

	@Override
	public void renderEdgeLabel(RenderContext<V, E> rc, Layout<V, E> layout, E e) {

		if (edgeLabelRenderer == null) {
			return;
		}

		Function<? super E, String> xform = rc.getEdgeLabelTransformer();
		String label = xform.apply(e);
		if (label == null) {
			return;
		}

		edgeLabelRenderer.labelEdge(rc, layout, e, xform.apply(e));
	}

}
