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
package ghidra.app.plugin.core.functiongraph.graph.jung.renderer;

import java.awt.Rectangle;
import java.awt.Shape;
import java.util.Set;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.visualization.RenderContext;
import edu.uci.ics.jung.visualization.transform.shape.GraphicsDecorator;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.graph.vertex.GroupedFunctionGraphVertex;
import ghidra.graph.viewer.vertex.VisualVertexRenderer;

public class FGVertexRenderer extends VisualVertexRenderer<FGVertex, FGEdge> {

	@Override
	protected void paintDropShadow(RenderContext<FGVertex, FGEdge> rc, GraphicsDecorator g,
			Shape shape, FGVertex vertex) {

		Rectangle bounds = shape.getBounds();
		if (vertex instanceof GroupedFunctionGraphVertex) {
			// paint depth images offset from main vertex
			Rectangle originalBounds = bounds;
			Rectangle paintBounds = (Rectangle) originalBounds.clone();
			Set<FGVertex> vertices = ((GroupedFunctionGraphVertex) vertex).getVertices();
			int offset = 15;
			int size = vertices.size();
			if (size > 3) {
				size = size / 3; // don't paint one-for-one, that's a bit much
				size = Math.max(size, 2);
			}
			int currentOffset = offset * size;
			for (int i = size - 1; i >= 0; i--) {
				paintBounds.x = originalBounds.x + currentOffset;
				paintBounds.y = originalBounds.y + currentOffset;
				currentOffset -= offset;
				super.paintDropShadow(rc, g, paintBounds);
			}
		}

		super.paintDropShadow(rc, g, bounds);
	}

	@Override
	protected void paintVertexOrVertexShape(RenderContext<FGVertex, FGEdge> rc, GraphicsDecorator g,
			Layout<FGVertex, FGEdge> layout, FGVertex vertex, Shape compactShape, Shape fullShape) {

		if (isScaledPastVertexPaintingThreshold(rc)) {
			paintScaledVertex(rc, vertex, g, compactShape);
			return;
		}

		if (vertex instanceof GroupedFunctionGraphVertex) {
			// paint depth images offset from main vertex
			Rectangle originalBounds = fullShape.getBounds();
			Rectangle paintBounds = (Rectangle) originalBounds.clone();
			Set<FGVertex> vertices = ((GroupedFunctionGraphVertex) vertex).getVertices();
			int offset = 5;
			int size = vertices.size();
			if (size > 3) {
				size = size / 3; // don't paint one-for-one, that's a bit much
				size = Math.max(size, 2);  // we want at least 2, to give some depth
			}
			int currentOffset = offset * size;
			for (int i = size - 1; i >= 0; i--) {
				paintBounds.x = originalBounds.x + currentOffset;
				paintBounds.y = originalBounds.y + currentOffset;
				currentOffset -= offset;
				paintVertex(rc, g, vertex, paintBounds, layout);
			}
		}

		// paint one final time
		Rectangle bounds = fullShape.getBounds();
		paintVertex(rc, g, vertex, bounds, layout);
	}

	@Override
	protected void paintVertex(RenderContext<FGVertex, FGEdge> rc, GraphicsDecorator g,
			FGVertex vertex, Rectangle bounds, Layout<FGVertex, FGEdge> layout) {

		refreshVertexAsNeeded(vertex);

		vertex.setShowing(true); // hack to make sure the component paints 
		super.paintVertex(rc, g, vertex, bounds, layout);
		vertex.setShowing(false); // turn off painting (this fix keeps tooltips from painting)
	}

	/**
	 * 	                     <center>Odd Code Alert!</center><br><p> 
	 *	 We use a lazy model for rebuilding the Listings inside of each vertex as the model's
	 *	 data changes.  We need a good place to tell the vertex to rebuild itself.  We 
	 *	 decided that placing the call to rebuild here inside of the paint code is the best 
	 *	 place because it will only happen when the vertex is actually being painted (i.e., 
	 *	 this paint call does not happen if the vertex is outside of the viewing area or
	 *	 if it is scaled past the interaction threshold).  Finally, calling this method is 
	 *	 not a performance problem, as the vertex's model will not rebuild itself if no 
	 *	 changes have been made
	 *	
	 */
	private void refreshVertexAsNeeded(FGVertex vertex) {
		vertex.refreshModel();
	}
}
