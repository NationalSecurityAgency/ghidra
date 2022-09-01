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
package ghidra.app.plugin.core.functiongraph.graph;

import java.awt.*;
import java.util.*;
import java.util.Map.Entry;

import org.jdom.Element;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.visualization.RenderContext;
import edu.uci.ics.jung.visualization.picking.PickedState;
import edu.uci.ics.jung.visualization.renderers.Renderer;
import edu.uci.ics.jung.visualization.util.Caching;
import generic.theme.GColor;
import ghidra.app.plugin.core.functiongraph.graph.jung.renderer.FGVertexRenderer;
import ghidra.app.plugin.core.functiongraph.graph.jung.transformer.FGVertexPickableBackgroundPaintTransformer;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayout;
import ghidra.app.plugin.core.functiongraph.graph.vertex.*;
import ghidra.app.plugin.core.functiongraph.mvc.*;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.layout.LayoutListener.ChangeType;
import ghidra.graph.viewer.layout.LayoutProvider;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.graph.viewer.renderer.VisualGraphEdgeLabelRenderer;
import ghidra.graph.viewer.vertex.AbstractVisualVertexRenderer;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.util.SystemUtilities;
import ghidra.util.UndefinedFunction;

public class FGComponent extends GraphComponent<FGVertex, FGEdge, FunctionGraph> {

	//@formatter:off
	private static final Color PICKED_COLOR = new GColor("color.bg.functiongraph.vertex.picked");
	private static final Color START_COLOR = new GColor("color.bg.functiongraph.vertex.entry");
	private static final Color END_COLOR = new GColor("color.bg.functiongraph.vertex.exit");	
	private static final Color UNDEFINED_FUNCTION_COLOR = new GColor("color.bg.undefined");
	//@formatter:on

	/**
	 * A somewhat arbitrary value that is used to signal a 'big' graph, which is one that will
	 * slow down the system during the rendering process.
	 */
	private static final int REALLY_BIG_FG_VERTEX_COUNT = 75;

	private final FGView functionGraphView;
	private FGData functionGraphData;
	private FunctionGraph functionGraph;

	public FGComponent(FGView functionGraphView, FGData data,
			LayoutProvider<FGVertex, FGEdge, FunctionGraph> layoutProvider) {

		// Note: we cannot call super here, as we need to set our variables below before 
		//       the base class builds.
		// super(data.getFunctionGraph());

		setGraphOptions(functionGraphView.getController().getFunctionGraphOptions());

		setGraph(data.getFunctionGraph());

		this.functionGraphView = functionGraphView;
		this.functionGraphData = data;
		this.functionGraph = data.getFunctionGraph();

		build();

		String message = data.getMessage();
		if (message != null) {
			setStatusMessage(message);
		}

		// Note: can't do this here due to timing...restoring the groups may trigger 
		// callbacks into the view code, which at the point of this constructor has 
		// not yet been initialized
		//
		// restoreSettings();
	}

	@Override
	protected FGVertex getInitialVertex() {
		FGVertex focused = super.getInitialVertex();
		if (focused == null) {
			return functionGraph.getRootVertex();
		}
		return focused;
	}

	@Override
	protected void zoomInCompletely(FGVertex v) {

		super.zoomInCompletely(v);

		FGVertex vertex = graph.getFocusedVertex();
		if (vertex == null) {
			return; // no graph
		}

		Rectangle cursorBounds = vertex.getCursorBounds();
		if (cursorBounds != null) {
			ensureCursorVisible(vertex);
			return;
		}

		// do later; the cursor has not yet been rendered when called from the initialization phase
		SystemUtilities.runSwingLater(() -> ensureCursorVisible(vertex));
	}

	public void restoreSettings() {
		restoreGroupedVertices();
		restoreVertexLocations();
	}

	private void restoreGroupedVertices() {
		FGController controller = functionGraphView.getController();
		Element groupedVertexXML = functionGraph.getSavedGroupedVertexSettings();
		if (groupedVertexXML != null) {
			GroupVertexSerializer.recreateGroupedVertices(controller, groupedVertexXML);
		}

		Element regroupVertexXML = functionGraph.getSavedGroupHistory();
		if (regroupVertexXML != null) {
			Collection<GroupHistoryInfo> history =
				GroupVertexSerializer.recreateGroupHistory(controller, regroupVertexXML);
			functionGraph.setGroupHistory(history);
		}
	}

	private FGLayout getFunctionGraphLayout() {
		Layout<FGVertex, FGEdge> graphLayout = primaryViewer.getVisualGraphLayout();
		FGLayout layout = (FGLayout) graphLayout;
		return layout;
	}

	private void restoreVertexLocations() {

		Map<FGVertex, Point> vertexLocations = functionGraph.getSavedVertexLocations();
		Set<Entry<FGVertex, Point>> entrySet = vertexLocations.entrySet();
		FGLayout layout = getFunctionGraphLayout();
		for (Entry<FGVertex, Point> entry : entrySet) {
			layout.setLocation(entry.getKey(), entry.getValue(), ChangeType.RESTORE);
		}

		// hack to make sure that location algorithms use the correct position values

		if (layout instanceof Caching) {
			((Caching) layout).clear();
		}

		VisualGraphViewUpdater<FGVertex, FGEdge> viewUpdater = getViewUpdater();
		if (isSatelliteShowing()) {
			viewUpdater.fitGraphToViewerNow(satelliteViewer);
		}

		Set<FGEdge> edges = new HashSet<>();
		Set<FGVertex> vertices = vertexLocations.keySet();
		for (FGVertex vertex : vertices) {
			edges.addAll(graph.getIncidentEdges(vertex));
		}
		viewUpdater.updateEdgeShapes(edges);

		repaint();
	}

	public void clearLayoutPositionCache() {
		functionGraph.clearSavedVertexLocations();
	}

	public void clearAllUserLayoutSettings() {
		functionGraph.clearAllUserLayoutSettings();
	}

	@Override
	protected void refreshCurrentLayout() {
		super.refreshCurrentLayout();
		functionGraphView.broadcastLayoutRefreshNeeded();
	}

	@Override
	protected FGPrimaryViewer createPrimaryGraphViewer(VisualGraphLayout<FGVertex, FGEdge> layout,
			Dimension viewerSize) {
		return new FGPrimaryViewer(this, layout, viewerSize);
	}

	@Override
	protected void decoratePrimaryViewer(GraphViewer<FGVertex, FGEdge> viewer,
			VisualGraphLayout<FGVertex, FGEdge> layout) {

		super.decoratePrimaryViewer(viewer, layout);

		// the edge renderer was set by the parent call; get the renderer to add our painter
		Renderer<FGVertex, FGEdge> renderer = viewer.getRenderer();
		RenderContext<FGVertex, FGEdge> renderContext = viewer.getRenderContext();

		// for background colors when we are zoomed to far to render the listing
		PickedState<FGVertex> pickedVertexState = viewer.getPickedVertexState();
		FGVertexRenderer vertexRenderer = new FGVertexRenderer();
		vertexRenderer.setVertexFillPaintTransformer(new FGVertexPickableBackgroundPaintTransformer(
			pickedVertexState, PICKED_COLOR, START_COLOR, END_COLOR));
		renderer.setVertexRenderer(vertexRenderer);

		// edge label rendering
		com.google.common.base.Function<FGEdge, String> edgeLabelTransformer = e -> e.getLabel();
		renderContext.setEdgeLabelTransformer(edgeLabelTransformer);

		// note: this label renderer is the stamp for the label; we use another edge label 
		//       renderer inside of the VisualGraphRenderer
		VisualGraphEdgeLabelRenderer edgeLabelRenderer =
			new VisualGraphEdgeLabelRenderer(new GColor("color.fg.label.picked"));
		edgeLabelRenderer.setNonPickedForegroundColor(new GColor("color.fg.label.non.picked"));
		edgeLabelRenderer.setRotateEdgeLabels(false);
		renderContext.setEdgeLabelRenderer(edgeLabelRenderer);

		viewer.setGraphOptions(vgOptions);
		Color bgColor = vgOptions.getGraphBackgroundColor();
		if (vgOptions.isDefaultBackgroundColor(bgColor)) {

			// Give user notice when seeing the graph for a non-function (such as an undefined 
			// function), as this is typical for Ghidra UI widgets.   
			// Don't do this if the user has manually set the background color (this would require 
			// another option).
			Function function = functionGraphData.getFunction();
			if (function instanceof UndefinedFunction) {
				viewer.setBackground(UNDEFINED_FUNCTION_COLOR);
			}
			else {
				viewer.setBackground(new GColor("color.bg.functiongraph"));
			}
		}

	}

	@Override
	protected void decorateSatelliteViewer(SatelliteGraphViewer<FGVertex, FGEdge> viewer,
			VisualGraphLayout<FGVertex, FGEdge> layout) {

		super.decorateSatelliteViewer(viewer, layout);

		// the edge renderer was set by the parent call; get the renderer to add our painter
		Renderer<FGVertex, FGEdge> renderer = viewer.getRenderer();

		AbstractVisualVertexRenderer<FGVertex, FGEdge> vertexRenderer =
			(AbstractVisualVertexRenderer<FGVertex, FGEdge>) renderer.getVertexRenderer();

		PickedState<FGVertex> pickedVertexState = viewer.getPickedVertexState();

		RenderContext<FGVertex, FGEdge> renderContext = viewer.getRenderContext();
		renderContext.setVertexFillPaintTransformer(new FGVertexPickableBackgroundPaintTransformer(
			pickedVertexState, PICKED_COLOR, START_COLOR, END_COLOR));
		vertexRenderer.setVertexFillPaintTransformer(new FGVertexPickableBackgroundPaintTransformer(
			pickedVertexState, PICKED_COLOR, START_COLOR, END_COLOR));

		viewer.setGraphOptions(vgOptions);
	}

	@Override
	protected boolean isReallyBigData() {
		return graph.getVertices().size() > REALLY_BIG_FG_VERTEX_COUNT;
	}

//==================================================================================================
// Accessor Methods
//==================================================================================================    

	@Override
	public void dispose() {
		// big assumption - the components below will be disposed by the controller, so we don't 
		// dispose them, as they may be cached
		functionGraph = null;
		functionGraphData = null;
		super.dispose();
	}

//==================================================================================================
// FG-specific Client Methods
//==================================================================================================

	public FunctionGraphOptions getFunctionGraphOptions() {
		return (FunctionGraphOptions) vgOptions;
	}

	public void ensureCursorVisible(FGVertex vertex) {

		VisualGraphViewUpdater<FGVertex, FGEdge> viewUpdater = getViewUpdater();
		Rectangle cursorBounds = vertex.getCursorBounds();
		if (cursorBounds != null) {
			viewUpdater.ensureVertexAreaVisible(vertex, cursorBounds, null);
			return;
		}

		// just make the entire vertex visible
		RenderContext<FGVertex, FGEdge> renderContext = primaryViewer.getRenderContext();
		com.google.common.base.Function<? super FGVertex, Shape> transformer =
			renderContext.getVertexShapeTransformer();
		Shape shape = transformer.apply(vertex);
		Rectangle bounds = shape.getBounds();
		viewUpdater.ensureVertexAreaVisible(vertex, bounds, null);
	}

	public void setVertexFocused(FGVertex v, ProgramLocation location) {

		//
		// NOTE: we must focus the vertex before we set the program location, as focusing the 
		// vertex will turn on the cursor, which allows the cursor to be properly set when we
		// set the location.  Reversing these two calls will not allow the cursor to be set 
		// properly.
		// 

		boolean wasFocused = v.isFocused();

		// As per the note above, the vertex must think it is focused to update its cursor, so
		// focus it, but DO NOT send out the event.  The 'pick to sync' will not trigger an 
		// API-wide notification of the focused vertex. 
		gPickedState.pickToSync(v);
		v.setProgramLocation(location);

		if (!wasFocused) {
			// was not focused; signal to the external API that there is a new vertex in town
			gPickedState.pickToActivate(v);
		}
	}
}
