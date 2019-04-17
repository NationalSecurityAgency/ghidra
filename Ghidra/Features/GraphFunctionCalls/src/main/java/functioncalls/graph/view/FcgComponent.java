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
package functioncalls.graph.view;

import java.awt.Color;

import edu.uci.ics.jung.visualization.RenderContext;
import functioncalls.graph.*;
import functioncalls.graph.renderer.FcgEdgePaintTransformer;
import functioncalls.graph.renderer.FcgVertexPaintTransformer;
import functioncalls.plugin.FunctionCallGraphPlugin;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.layout.VisualGraphLayout;

/**
 * A graph component for the {@link FunctionCallGraphPlugin}
 */
public class FcgComponent extends GraphComponent<FcgVertex, FcgEdge, FunctionCallGraph> {

	// our parent stores a reference to this graph, but we do it here to maintain its type
	private FunctionCallGraph fcGraph;

	// TODO use options for color
	private FcgVertexPaintTransformer vertexPaintTransformer =
		new FcgVertexPaintTransformer(FcgVertex.DEFAULT_VERTEX_SHAPE_COLOR);

	private Color lightGreen = new Color(143, 197, 143);
	private Color lightGray = new Color(233, 233, 233);

	// the satellite gets too cluttered, so wash out the edges
	private Color washedOutBlack = new Color(0, 0, 0, 25);

	private FcgEdgePaintTransformer edgePaintTransformer =
		new FcgEdgePaintTransformer(lightGreen, lightGray);
	private FcgEdgePaintTransformer satelliteEdgePaintTransformer =
		new FcgEdgePaintTransformer(washedOutBlack, new Color(125, 125, 125, 25));

	FcgComponent(FunctionCallGraph g) {

		setGraph(g);
		build();
	}

	@Override
	protected FcgVertex getInitialVertex() {
		return fcGraph.getSource();
	}

	@Override
	protected void decoratePrimaryViewer(GraphViewer<FcgVertex, FcgEdge> viewer,
			VisualGraphLayout<FcgVertex, FcgEdge> layout) {

		super.decoratePrimaryViewer(viewer, layout);

		RenderContext<FcgVertex, FcgEdge> renderContext = viewer.getRenderContext();
		renderContext.setVertexFillPaintTransformer(vertexPaintTransformer);

		// Note: setting the fill for the edges has the effect of drawing a filled-in circle
		//       instead of just the outer edge.
		// renderContext.setEdgeFillPaintTransformer(edgePaintTransformer);
		renderContext.setEdgeDrawPaintTransformer(edgePaintTransformer);
		renderContext.setArrowFillPaintTransformer(edgePaintTransformer);
		renderContext.setArrowDrawPaintTransformer(edgePaintTransformer);

	}

	@Override
	protected void decorateSatelliteViewer(SatelliteGraphViewer<FcgVertex, FcgEdge> viewer,
			VisualGraphLayout<FcgVertex, FcgEdge> layout) {

		super.decorateSatelliteViewer(viewer, layout);

		RenderContext<FcgVertex, FcgEdge> renderContext = viewer.getRenderContext();
		renderContext.setVertexFillPaintTransformer(vertexPaintTransformer);
		//renderContext.setEdgeFillPaintTransformer(satelliteEdgePaintTransformer);
		renderContext.setEdgeDrawPaintTransformer(satelliteEdgePaintTransformer);
		renderContext.setArrowFillPaintTransformer(satelliteEdgePaintTransformer);
		renderContext.setArrowDrawPaintTransformer(satelliteEdgePaintTransformer);
	}

	@Override
	public void dispose() {

		fcGraph = null;
		super.dispose();
	}

	@Override // open access for testing
	public VisualGraphViewUpdater<FcgVertex, FcgEdge> getViewUpdater() {
		return super.getViewUpdater();
	}
}
