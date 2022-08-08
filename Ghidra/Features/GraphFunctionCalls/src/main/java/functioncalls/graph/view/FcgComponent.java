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

import edu.uci.ics.jung.visualization.renderers.Renderer;
import functioncalls.graph.*;
import functioncalls.graph.renderer.FcgEdgePaintTransformer;
import functioncalls.graph.renderer.FcgVertexPaintTransformer;
import functioncalls.plugin.FunctionCallGraphPlugin;
import generic.theme.GColor;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.edge.VisualEdgeRenderer;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.graph.viewer.renderer.VisualVertexSatelliteRenderer;
import ghidra.graph.viewer.vertex.VisualVertexRenderer;

/**
 * A graph component for the {@link FunctionCallGraphPlugin}
 */
public class FcgComponent extends GraphComponent<FcgVertex, FcgEdge, FunctionCallGraph> {

	// our parent stores a reference to this graph, but we do it here to maintain its type
	private FunctionCallGraph fcGraph;

	private FcgVertexPaintTransformer vertexPaintTransformer =
		new FcgVertexPaintTransformer(FcgVertex.DEFAULT_VERTEX_SHAPE_COLOR);

	private FcgEdgePaintTransformer edgePaintTransformer =
		new FcgEdgePaintTransformer(new GColor("color.bg.fcg.edge.primary.direct"),
			new GColor("color.bg.fcg.edge.primary.indirect"));
	private FcgEdgePaintTransformer selectedEdgePaintTransformer =
		new FcgEdgePaintTransformer(new GColor("color.bg.fcg.edge.primary.direct.selected"),
			new GColor("color.bg.fcg.edge.primary.indirect.selected"));
	private FcgEdgePaintTransformer satelliteEdgePaintTransformer =
		new FcgEdgePaintTransformer(new GColor("color.bg.fcg.edge.satellite.direct"),
			new GColor("color.bg.fcg.edge.satellite.indirect"));

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

		Renderer<FcgVertex, FcgEdge> renderer = viewer.getRenderer();
		VisualVertexRenderer<FcgVertex, FcgEdge> vertexRenderer =
			(VisualVertexRenderer<FcgVertex, FcgEdge>) renderer.getVertexRenderer();
		vertexRenderer.setVertexFillPaintTransformer(vertexPaintTransformer);

		VisualEdgeRenderer<FcgVertex, FcgEdge> edgeRenderer =
			(VisualEdgeRenderer<FcgVertex, FcgEdge>) renderer.getEdgeRenderer();
		edgeRenderer.setDrawColorTransformer(edgePaintTransformer);
		edgeRenderer.setSelectedColorTransformer(selectedEdgePaintTransformer);
	}

	@Override
	protected void decorateSatelliteViewer(SatelliteGraphViewer<FcgVertex, FcgEdge> viewer,
			VisualGraphLayout<FcgVertex, FcgEdge> layout) {

		super.decorateSatelliteViewer(viewer, layout);

		Renderer<FcgVertex, FcgEdge> renderer = viewer.getRenderer();
		VisualVertexSatelliteRenderer<FcgVertex, FcgEdge> vertexRenderer =
			(VisualVertexSatelliteRenderer<FcgVertex, FcgEdge>) renderer.getVertexRenderer();
		vertexRenderer.setVertexFillPaintTransformer(vertexPaintTransformer);

		VisualEdgeRenderer<FcgVertex, FcgEdge> edgeRenderer =
			(VisualEdgeRenderer<FcgVertex, FcgEdge>) renderer.getEdgeRenderer();
		edgeRenderer.setDrawColorTransformer(satelliteEdgePaintTransformer);
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
