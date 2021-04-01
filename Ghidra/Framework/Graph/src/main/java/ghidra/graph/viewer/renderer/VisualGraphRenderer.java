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

import java.awt.Color;
import java.awt.geom.Point2D;
import java.util.*;

import com.google.common.base.Function;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.visualization.*;
import edu.uci.ics.jung.visualization.layout.ObservableCachingLayout;
import edu.uci.ics.jung.visualization.renderers.Renderer;
import edu.uci.ics.jung.visualization.transform.shape.GraphicsDecorator;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.edge.BasicEdgeLabelRenderer;
import ghidra.graph.viewer.layout.*;

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

	/**
	 * Used for displaying grid information for graph layouts
	 */
	public static Map<VisualGraphLayout<?, ?>, LayoutLocationMap<?, ?>> DEBUG_ROW_COL_MAP =
		new HashMap<>();

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

		paintLayoutGridCells(renderContext, layout);
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

	@SuppressWarnings({ "unchecked", "rawtypes" }) // the types in the cast matter not
	private void paintLayoutGridCells(RenderContext<V, E> renderContext, Layout<V, E> layout) {

		// to enable this debug, search java files for commented-out uses of 'DEBUG_ROW_COL_MAP'
		Layout<V, E> key = layout;
		if (layout instanceof ObservableCachingLayout) {
			key = ((ObservableCachingLayout) layout).getDelegate();
		}
		LayoutLocationMap<?, ?> locationMap = DEBUG_ROW_COL_MAP.get(key);
		if (locationMap == null) {
			return;
		}

		int rowCount = locationMap.getRowCount();
		if (rowCount == 0) {
			return; // ?
		}

		GraphicsDecorator g = renderContext.getGraphicsContext();
		Color originalColor = g.getColor();
		Color gridColor = Color.ORANGE;
		Color textColor = Color.BLACK;

		boolean isCondensed = locationMap.isCondensed();
		Row<?> lastRow = locationMap.lastRow();
		Column lastColumn = locationMap.lastColumn();

		if (lastRow == null || lastColumn == null) {
			return; // empty graph?
		}

		int width = lastColumn.x + lastColumn.getPaddedWidth(isCondensed);
		int height = lastRow.y + lastRow.getPaddedHeight(isCondensed);

		MultiLayerTransformer transformer = renderContext.getMultiLayerTransformer();
		for (Row<?> row : locationMap.rows()) {
			Point2D start = new Point2D.Double(0, row.y);
			start = transformer.transform(Layer.LAYOUT, start);
			g.setColor(textColor);
			g.drawString(Integer.toString(row.index), (float) start.getX() - 20,
				(float) (start.getY() + 5));

			Point2D end = new Point2D.Double(width, row.y);
			end = transformer.transform(Layer.LAYOUT, end);
			g.setColor(gridColor);
			g.drawLine((int) start.getX(), (int) start.getY(), (int) end.getX(), (int) end.getY());
		}

		// close the grid
		Point2D start = new Point2D.Double(0, lastRow.y + lastRow.getPaddedHeight(isCondensed));
		start = transformer.transform(Layer.LAYOUT, start);
		Point2D end = new Point2D.Double(width, lastRow.y + lastRow.getPaddedHeight(isCondensed));
		end = transformer.transform(Layer.LAYOUT, end);
		g.drawLine((int) start.getX(), (int) start.getY(), (int) end.getX(), (int) end.getY());

		for (Column column : locationMap.columns()) {
			start = new Point2D.Double(column.x, 0);
			start = transformer.transform(Layer.LAYOUT, start);
			g.setColor(textColor);
			g.drawString(Integer.toString(column.index), (float) start.getX() - 5,
				(float) (start.getY() - 10));

			end = new Point2D.Double(column.x, height);
			end = transformer.transform(Layer.LAYOUT, end);
			g.setColor(gridColor);
			g.drawLine((int) start.getX(), (int) start.getY(), (int) end.getX(), (int) end.getY());
		}

		// close the grid
		start = new Point2D.Double(lastColumn.x + lastColumn.getPaddedWidth(isCondensed), 0);
		start = transformer.transform(Layer.LAYOUT, start);
		end = new Point2D.Double(lastColumn.x + lastColumn.getPaddedWidth(isCondensed), height);
		end = transformer.transform(Layer.LAYOUT, end);
		g.drawLine((int) start.getX(), (int) start.getY(), (int) end.getX(), (int) end.getY());

		g.setColor(originalColor);
	}
}
