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

import static org.jungrapht.visualization.renderers.BiModalRenderer.*;

import java.awt.*;
import java.awt.event.*;
import java.awt.geom.Point2D;
import java.util.*;
import java.util.List;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import javax.swing.*;

import org.jgrapht.Graph;
import org.jungrapht.visualization.*;
import org.jungrapht.visualization.annotations.MultiSelectedVertexPaintable;
import org.jungrapht.visualization.annotations.SingleSelectedVertexPaintable;
import org.jungrapht.visualization.control.*;
import org.jungrapht.visualization.decorators.*;
import org.jungrapht.visualization.layout.algorithms.LayoutAlgorithm;
import org.jungrapht.visualization.layout.model.LayoutModel;
import org.jungrapht.visualization.layout.model.Point;
import org.jungrapht.visualization.renderers.*;
import org.jungrapht.visualization.renderers.Renderer;
import org.jungrapht.visualization.selection.MutableSelectedState;
import org.jungrapht.visualization.transform.*;
import org.jungrapht.visualization.transform.shape.MagnifyImageLensSupport;
import org.jungrapht.visualization.transform.shape.MagnifyShapeTransformer;

import docking.ActionContext;
import docking.action.builder.*;
import docking.menu.ActionState;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.graph.AttributeFilters;
import ghidra.graph.job.GraphJobRunner;
import ghidra.service.graph.*;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;
import resources.Icons;
import util.CollectionUtils;

/**
 * Delegates to a {@link VisualizationViewer} to draw a graph visualization
 */
public class DefaultGraphDisplay implements GraphDisplay {
	public static final String FAVORED_EDGE = "Fall-Through";
	private static final int MAX_NODES = 10000;
	public static final Dimension PREFERRED_VIEW_SIZE = new Dimension(1000, 1000);
	public static final Dimension PREFERRED_LAYOUT_SIZE = new Dimension(3000, 3000);

	Logger log = Logger.getLogger(DefaultGraphDisplay.class.getName());

	private GraphDisplayListener listener = new DummyGraphDisplayListener();
	private String description;

	/**
	 * the {@link Graph} to visualize
	 */
	private AttributedGraph graph;

	/**
	 * a unique id for this {@link GraphDisplay}
	 */
	private final int displayId;

	/**
	 * the delegate viewer to display the ProgramGraph
	 */
	private VisualizationViewer<AttributedVertex, AttributedEdge> viewer;

	/**
	 * the {@link PluginTool}
	 */
	private PluginTool pluginTool;

	/**
	 * the {@link Plugin} that manages this {@link GraphDisplay}
	 */
	private String pluginName = "ProgramGraphPlugin";

	/**
	 * provides the component for the {@link GraphDisplay}
	 */
	private DefaultGraphDisplayComponentProvider componentProvider;

	/**
	 * whether to scroll the visualization in order to center the selected vertex
	 * (or the centroid of the selected vertices)
	 */
	private boolean enableScrollToSelection = false;

	/**
	 * allows selection of various {@link LayoutAlgorithm} ('arrangements')
	 */
	private LayoutTransitionManager layoutTransitionManager;

	/**
	 * manages highlight painting of a single selected vertex
	 */
	private SingleSelectedVertexPaintable<AttributedVertex, AttributedEdge> singleSelectedVertexPaintable;
	private MultiSelectedVertexPaintable<AttributedVertex, AttributedEdge> multiSelectedVertexPaintable;
	private DefaultGraphDisplayProvider graphDisplayProvider;

	/**
	 * Create the initial display, the graph-less visualization viewer, and its controls
	 * @param displayProvider provides a {@link PluginTool} for Docking features
	 * @param id the unique display id
	 */
	DefaultGraphDisplay(DefaultGraphDisplayProvider displayProvider, int id) {
		this.graphDisplayProvider = displayProvider;
		this.displayId = id;
		this.pluginTool = graphDisplayProvider.getPluginTool();
		this.viewer = createViewer();

		buildHighlighers();

		componentProvider = new DefaultGraphDisplayComponentProvider(this, pluginTool);
		componentProvider.addToTool();
		satelliteViewer = createSatelliteViewer(viewer);
		layoutTransitionManager =
			new LayoutTransitionManager(viewer, this::isRoot, this::isFavoredEdge);

		viewer.getComponent().addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				super.componentResized(e);
				Component vv = e.getComponent();
				Dimension vvd = vv.getSize();
				Dimension sd = satelliteViewer.getSize();
				java.awt.Point p = new java.awt.Point(vvd.width - sd.width, vvd.height - sd.height);
				satelliteViewer.getComponent().setBounds(p.x, p.y, sd.width, sd.height);
			}
		});

		createActions();
		connectSelectionStateListeners();
	}

	JComponent getComponent() {
		JComponent component = viewer.getComponent();
		component.setFocusable(true);
		return component;
	}

	int getId() {
		return displayId;
	}

	private LensSupport<LensGraphMouse> createManifiers() {
		Lens lens = Lens.builder().lensShape(Lens.Shape.RECTANGLE).magnification(3.f).build();
		lens.setMagnification(2.f);
		LensMagnificationGraphMousePlugin magnificationPlugin =
			new LensMagnificationGraphMousePlugin(1.f, 60.f, .2f);

		MutableTransformer transformer = viewer.getRenderContext()
				.getMultiLayerTransformer()
				.getTransformer(MultiLayerTransformer.Layer.VIEW);

		MagnifyShapeTransformer shapeTransformer = MagnifyShapeTransformer.builder(lens)
				// this lens' delegate is the viewer's VIEW layer
				.delegate(transformer)
				.build();

		return MagnifyImageLensSupport.builder(viewer)
				.lensTransformer(shapeTransformer)
				.lensGraphMouse(new DefaultLensGraphMouse<>(magnificationPlugin))
				.build();
	}

	private void buildHighlighers() {
		// for highlighting of multiple selected vertices
		this.multiSelectedVertexPaintable = MultiSelectedVertexPaintable.builder(viewer)
				.selectionStrokeMin(4.f)
				.selectionPaint(Color.red)
				.useBounds(true)
				.build();

		// for highlighting of single 'located' vertices
		this.singleSelectedVertexPaintable = SingleSelectedVertexPaintable.builder(viewer)
				.selectionStrokeMin(4.f)
				.selectionPaint(Color.red)
				.build();

		// this draws the selection highlights
		viewer.addPostRenderPaintable(multiSelectedVertexPaintable);

		// this draws the location arrow
		viewer.addPostRenderPaintable(singleSelectedVertexPaintable);

	}

	private void createActions() {

		// create a toggle for 'scroll to selected vertex'
		new ToggleActionBuilder("Scroll To Selection", pluginName)
				.toolBarIcon(Icons.NAVIGATE_ON_INCOMING_EVENT_ICON)
				.description("Scroll to Selection")
				.selected(false)
				.onAction(context -> enableScrollToSelection =
					((AbstractButton) context.getSourceObject()).isSelected())
				.buildAndInstallLocal(componentProvider);

		// create an icon button to display the satellite view
		new ToggleActionBuilder("SatelliteView", pluginName).description("Show Satellite View")
				.toolBarIcon(DefaultDisplayGraphIcons.SATELLITE_VIEW_ICON)
				.onAction(this::toggleSatellite)
				.buildAndInstallLocal(componentProvider);

		// create an icon button to reset the view transformations to identity (scaled to layout)
		new ActionBuilder("Reset View", pluginName).description("Reset all view transforms")
				.toolBarIcon(Icons.REFRESH_ICON)
				.onAction(context -> {
					viewer.reset();
					viewer.scaleToLayout(true);
				})
				.buildAndInstallLocal(componentProvider);

		// create a button to show the view magnify lens
		LensSupport<LensGraphMouse> magnifyViewSupport = createManifiers();
		@SuppressWarnings("unchecked")
		LensSupport<LensGraphMouse>[] lenses = new LensSupport[] { magnifyViewSupport };
		new ActionBuilder("View Magnifier", pluginName).description("Show View Magnifier")
				.toolBarIcon(DefaultDisplayGraphIcons.VIEW_MAGNIFIER_ICON)
				.onAction(context -> {
					Arrays.stream(lenses).forEach(LensSupport::deactivate);
					magnifyViewSupport.activate();
				})
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Show Filters", pluginName).description("Show Graph Filters")
				.toolBarIcon(Icons.CONFIGURE_FILTER_ICON)
				.onAction(context -> showFilterDialog())
				.buildAndInstallLocal(componentProvider);
		
		new MultiStateActionBuilder<String>("Arrangement", pluginName)
				.description("Select Layout Arrangement")
				.toolBarIcon(DefaultDisplayGraphIcons.LAYOUT_ALGORITHM_ICON)
				.onActionStateChanged((s, t) -> layoutChanged(s.getName()))
				.addStates(getLayoutActionStates())
				.buildAndInstallLocal(componentProvider);
		
	}

	private List<ActionState<String>> getLayoutActionStates() {
		String[] names = layoutTransitionManager.getLayoutNames();
		List<ActionState<String>> actionStates = new ArrayList<>();
		for (String layoutName : names) {
			actionStates.add(new ActionState<String>(layoutName,
				DefaultDisplayGraphIcons.LAYOUT_ALGORITHM_ICON, layoutName));
		}
		return actionStates;
	}

	private void layoutChanged(String layoutName) {
		if (layoutTransitionManager != null) {
			layoutTransitionManager.setLayout(layoutName);
		}
	}

	private void showFilterDialog() {
		if (filterDialog == null) {
			if (vertexFilters == null) {
				Msg.showWarn(this, null, "No Graph", "Can't set filters with no graph present!");
				return;
			}
			filterDialog = new FilterDialog(vertexFilters.getButtons(), edgeFilters.getButtons());
		}
		componentProvider.getTool().showDialog(filterDialog);
	}

	private void toggleSatellite(ActionContext context) {
		if (((AbstractButton) context.getSourceObject()).isSelected()) {
			viewer.getComponent().add(satelliteViewer.getComponent());
		}
		else {
			viewer.getComponent().remove(satelliteViewer.getComponent());
		}
		viewer.repaint();

	}

	/**
	 * create a SatelliteViewer for the Visualization
	 * @param parentViewer the main visualization 'parent' of the satellite view
	 * @return a new SatelliteVisualizationViewer
	 */
	private SatelliteVisualizationViewer<AttributedVertex, AttributedEdge> createSatelliteViewer(
			VisualizationViewer<AttributedVertex, AttributedEdge> parentViewer) {
		final SatelliteVisualizationViewer<AttributedVertex, AttributedEdge> satelliteViewer =
			SatelliteVisualizationViewer.builder(parentViewer)
					.viewSize(new Dimension(250, 250))
					.build();
		satelliteViewer.setGraphMouse(new DefaultSatelliteGraphMouse<>());
		satelliteViewer.getRenderContext().setEdgeDrawPaintFunction(Colors::getColor);
		satelliteViewer.getRenderContext()
				.setEdgeStrokeFunction(ProgramGraphFunctions::getEdgeStroke);
		satelliteViewer.getRenderContext().setVertexFillPaintFunction(Colors::getColor);
		satelliteViewer.scaleToLayout();
		satelliteViewer.getRenderContext().setVertexLabelFunction(n -> null);
		satelliteViewer.getComponent().setBorder(BorderFactory.createEtchedBorder());
		return satelliteViewer;
	}

	@Override
	public void close() {
		graphDisplayProvider.remove(this);
		if (listener != null) {
			listener.graphClosed();
		}
		listener = null;
	}

	@Override
	public void setGraphDisplayListener(GraphDisplayListener listener) {
		if (this.listener != null) {
			this.listener.graphClosed();
		}
		this.listener = listener;
	}

	/**
	 * connect the selection state to to the visualization
	 */
	private void connectSelectionStateListeners() {
		viewer.getSelectedVertexState().addItemListener(e -> Swing.runLater(() -> {
			if (e.getStateChange() == ItemEvent.SELECTED) {
				Collection<AttributedVertex> selectedVertices = getVertices(e.getItem());
				List<String> selectedVertexIds = toVertexIds(selectedVertices);
				notifySelectionChanged(selectedVertexIds);

				AttributedVertex vertex = CollectionUtils.any(selectedVertices);
				if (vertex != null) {
					notifyLocationChanged(vertex.getId());
				}
			}
			else if (e.getStateChange() == ItemEvent.DESELECTED) {
				notifySelectionChanged(Collections.emptyList());
			}
			viewer.repaint();
		}));
	}

	private List<String> toVertexIds(Collection<AttributedVertex> selectedVertices) {
		return selectedVertices.stream().map(v -> v.getId()).collect(Collectors.toList());
	}

	@SuppressWarnings("unchecked")
	private Collection<AttributedVertex> getVertices(Object item) {
		if (item instanceof Collection) {
			return (Collection<AttributedVertex>) item;
		}
		else if (item instanceof AttributedVertex) {
			return List.of((AttributedVertex) item);
		}
		return Collections.emptyList();
	}

	private void notifySelectionChanged(List<String> vertexIds) {
		Swing.runLater(() -> listener.selectionChanged(vertexIds));
	}

	private void notifyLocationChanged(String vertexId) {
		Swing.runLater(() -> listener.locationChanged(vertexId));
	}

	/**
	 * Pass the supplied list of vertex id's to the underlying visualization to cause them to be 'selected' visually
	 * @param vertexIdList the vertex ids to select
	 */
	@Override
	public void selectVertices(List<String> vertexIdList) {
		MutableSelectedState<AttributedVertex> nodeSelectedState = viewer.getSelectedVertexState();
		Set<AttributedVertex> selected = getVertices(vertexIdList);
		if (vertexIdList.isEmpty()) {
			nodeSelectedState.clear();
		}
		else if (!Arrays.asList(nodeSelectedState.getSelectedObjects()).containsAll(selected)) {
			nodeSelectedState.clear();
			nodeSelectedState.select(selected, false);
			scrollToSelected(selected);
		}
		viewer.repaint();
	}

	private Set<AttributedVertex> getVertices(Collection<String> vertexIds) {
		Set<String> vertexSet = new HashSet<>(vertexIds);
		return graph.vertexSet()
				.stream()
				.filter(v -> vertexSet.contains(v.getId()))
				.collect(Collectors.toSet());
	}

	@Override
	public void setLocation(String vertexID) {
		Optional<AttributedVertex> selected =
			graph.vertexSet().stream().filter(v -> vertexID.equals(v.getId())).findFirst();
		log.fine("picking address:" + vertexID + " returned " + selected);
		viewer.repaint();
		selected.ifPresent(this::scrollToSelected);
		viewer.repaint();
	}

	/**
	 * set the {@link AttributedGraph} for visualization
	 * @param attributedGraph the {@link AttributedGraph} to visualize
	 */
	private void doSetGraphData(AttributedGraph attributedGraph) {
		graph = attributedGraph;

		layoutTransitionManager.setGraph(graph);

		configureViewerPreferredSize();

		Swing.runNow(() -> viewer.getVisualizationModel().setGraph(graph));

		configureFilters();

		LayoutAlgorithm<AttributedVertex> initialLayoutAlgorithm =
			layoutTransitionManager.getInitialLayoutAlgorithm(graph);

		viewer.getVisualizationModel().setLayoutAlgorithm(initialLayoutAlgorithm);

		viewer.scaleToLayout();

		componentProvider.setVisible(true);
	}

	/**
	 * Determines if a vertex is a root.  For our purpose, a root either has no incomming edges
	 * or has at least one outgoing "favored" edge and no incomming "favored" edge
	 * @param vertex the vertex to test if it is a root
	 * @return true if the vertex is a root
	 */
	private boolean isRoot(AttributedVertex vertex) {
		Set<AttributedEdge> incomingEdgesOf = graph.incomingEdgesOf(vertex);
		if (incomingEdgesOf.isEmpty()) {
			return true;
		}
		Set<AttributedEdge> outgoingEdgesOf = graph.outgoingEdgesOf(vertex);
		return outgoingEdgesOf.stream().anyMatch(this::isFavoredEdge) &&
			incomingEdgesOf.stream().noneMatch(this::isFavoredEdge);
	}



	private void configureFilters() {
		// close and rebuild filter dialog if exists
		if (filterDialog != null) {
			filterDialog.close();
			filterDialog = null;
		}
		Set<AttributedVertex> vertices = graph.vertexSet();
		Set<AttributedEdge> edges = graph.edgeSet();
		vertexFilters = AttributeFilters.builder()
				.exclude(Set.of("Address", "Code", "Name"))
				.elements(vertices)
				.maxFactor(.05)
				.buttonSupplier(JRadioButton::new)
				.paintFunction(v -> Colors.VERTEX_TYPE_TO_COLOR_MAP.getOrDefault(v, Color.blue))
				.build();

		vertexFilters.addItemListener(item -> {
			@SuppressWarnings("unchecked")
			Set<String> selected = (Set<String>) item.getItem();
			viewer.getRenderContext()
					.setVertexIncludePredicate(
						v -> v.getAttributeMap().values().stream().noneMatch(selected::contains));
			viewer.repaint();
		});

		edgeFilters = AttributeFilters.builder()
				.exclude(Set.of("*ToKey", "*FromKey", "Address", "Name"))
				.elements(edges)
				.maxFactor(.01)
				.buttonSupplier(JRadioButton::new)
				.paintFunction(e -> Colors.EDGE_TYPE_TO_COLOR_MAP.getOrDefault(e, Color.green))
				.build();

		edgeFilters.addItemListener(item -> {
			@SuppressWarnings("unchecked")
			Set<String> selected = (Set<String>) item.getItem();
			viewer.getRenderContext()
					.setEdgeIncludePredicate(
						e -> e.getAttributeMap().values().stream().noneMatch(selected::contains));
			viewer.repaint();
		});


	}

	private void configureViewerPreferredSize() {
		int vertexCount = graph.vertexSet().size();
		// attempt to set a reasonable size for the layout based on the number of vertices
		Dimension viewSize = viewer.getPreferredSize();
		if (vertexCount < 100) {
			viewer.getVisualizationModel()
					.getLayoutModel()
					.setPreferredSize(viewSize.width, viewSize.height);
		}
		else {
			int newSize = viewSize.width + 5 * (vertexCount - 100);
			viewer.getVisualizationModel().getLayoutModel().setPreferredSize(newSize, newSize);
		}
	}

	@Override
	public void defineVertexAttribute(String attributeName) {
		log.fine("defineVertexAttribute " + attributeName + " is not implemented");
	}

	@Override
	public void defineEdgeAttribute(String attributeName) {
		log.fine("defineEdgeAttribute " + attributeName + " is not implemented");
	}

	/*
	 * @see ghidra.program.model.graph.GraphDisplay#setVertexLabel(java.lang.String, int, int, boolean, int)
	 */
	@Override
	public void setVertexLabel(String attributeName, int alignment, int size, boolean monospace,
			int maxLines) {
		log.fine("setVertexLabel " + attributeName);
		// this would have to set the label function, the label font function
	}

	@Override
	public void setGraph(AttributedGraph graph, String description, boolean append,
			TaskMonitor monitor) {
		iconCache.clear();

		if (append && Objects.equals(description, this.description) && this.graph != null) {
			graph = mergeGraphs(graph, this.graph);
		}

		this.description = description;
		int count = graph.getVertexCount();
		if (count > MAX_NODES) {
			Msg.showWarn(this, null, "Graph Not Rendered - Too many nodes!",
				"Exceeded limit of " + MAX_NODES + " nodes.\n\n  Graph contained " + count +
					" nodes!");
			graph = new AttributedGraph();
			graph.addVertex("1", "Graph Aborted");
		}
		doSetGraphData(graph);
	}

	private AttributedGraph mergeGraphs(AttributedGraph newGraph, AttributedGraph oldGraph) {
		for (AttributedVertex vertex : oldGraph.vertexSet()) {	
			newGraph.addVertex(vertex);
		}
		for (AttributedEdge edge : oldGraph.edgeSet()) {
			AttributedVertex from = oldGraph.getEdgeSource(edge);
			AttributedVertex to = oldGraph.getEdgeTarget(edge);
			AttributedEdge newEdge = newGraph.addEdge(from, to);
			Map<String, String> attributeMap = edge.getAttributeMap();
			for (String key : attributeMap.keySet()) {
				newEdge.setAttribute(key, edge.getAttribute(key));
			}
		}
		return newGraph;
	}

	public void centerAndScale() {
		viewer.reset();
		viewer.scaleToLayout();
	}

	/**
	 * remove all vertices and edges from the {@link Graph}
	 */
	@Override
	public void clear() {
		this.graph.removeAllEdges(new HashSet<>(graph.edgeSet()));
		this.graph.removeAllVertices(new HashSet<>(graph.vertexSet()));
	}

	/**
	 * scroll the visualization to center the passed vertices
	 * @param vertices the vertices to center
	 */
	void scrollToSelected(Collection<AttributedVertex> vertices) {

		if (!enableScrollToSelection) {
			return;
		}

		Point2D newCenter = getPointToCenter(vertices);
		Point2D existingCenter = viewer.getRenderContext()
				.getMultiLayerTransformer()
				.inverseTransform(viewer.getCenter());

		jobRunner.schedule(new CenterAnimation(viewer, existingCenter, newCenter));
	}

	/**w
	 * scroll the visualization to center the passed vertex
	 * @param vertex the vertex to center
	 */
	void scrollToSelected(AttributedVertex vertex) {
		List<AttributedVertex> vertices =
			vertex == null ? Collections.emptyList() : List.of(vertex);
		scrollToSelected(vertices);
	}

	private Point2D getPointToCenter(Collection<AttributedVertex> vertices) {
		LayoutModel<AttributedVertex> layoutModel = viewer.getVisualizationModel().getLayoutModel();

		Collection<Point> points = vertices.stream().map(layoutModel).collect(Collectors.toList());

		if (points.size() > 0) {
			// center the selected vertices
			Point p = Point.centroidOf(points);
			return new Point2D.Double(p.x, p.y);
		}

		// they did not pick a vertex to center, so
		// just center the graph
		Point2D center = viewer.getCenter();
		Point p = Point.of(center.getX(), center.getY());
		return new Point2D.Double(p.x, p.y);
	}

	private GraphJobRunner jobRunner = new GraphJobRunner();
	private SatelliteVisualizationViewer<AttributedVertex, AttributedEdge> satelliteViewer;
	private AttributeFilters edgeFilters;
	private AttributeFilters vertexFilters;
	private FilterDialog filterDialog;
	private GhidraIconCache iconCache;

	@Override
	public void updateVertexName(String id, String newName) {
		// unsupported
	}

	@Override
	public String getGraphDescription() {
		return description;
	}

	private boolean isFavoredEdge(AttributedEdge edge) {
		if (edge.getAttributeMap().containsKey("EdgeType")) {
			return edge.getAttributeMap().getOrDefault("EdgeType", "NOTEQUAL").equals(FAVORED_EDGE);
		}
		return true;
	}

	public VisualizationViewer<AttributedVertex, AttributedEdge> createViewer() {
		final VisualizationViewer<AttributedVertex, AttributedEdge> vv =
			VisualizationViewer.<AttributedVertex, AttributedEdge> builder()
					.viewSize(PREFERRED_VIEW_SIZE)
					.layoutSize(PREFERRED_LAYOUT_SIZE)
					.build();

		// Add a component listener to scale and center the graph after the component
		// has been initially sized. Remove the listener after the first time so that any 
		// subsequent resizing does not affect the graph.
		vv.getComponent().addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				vv.getComponent().removeComponentListener(this);
				Swing.runLater(() -> {
					vv.reset();
					vv.scaleToLayout();
				});
			}
		});

		vv.setVertexToolTipFunction(AttributedVertex::getHtmlString);
		vv.setEdgeToolTipFunction(AttributedEdge::getHtmlString);
		RenderContext<AttributedVertex, AttributedEdge> renderContext = vv.getRenderContext();

		iconCache = new GhidraIconCache();

		// set up the shape and color functions
		IconShapeFunction<AttributedVertex> nodeImageShapeFunction =
			new IconShapeFunction<>(new EllipseShapeFunction<>());

		vv.getRenderContext().setVertexIconFunction(iconCache::get);

		// cause the vertices to be drawn with custom icons/shapes
		nodeImageShapeFunction.setIconFunction(iconCache::get);
		renderContext.setVertexShapeFunction(nodeImageShapeFunction);
		renderContext.setVertexIconFunction(iconCache::get);

		// selected edges will be drawn with a wider stroke
		renderContext.setEdgeStrokeFunction(
			e -> renderContext.getSelectedEdgeState().isSelected(e) ? new BasicStroke(20.f)
					: ProgramGraphFunctions.getEdgeStroke(e));
		// selected edges will be drawn in red (instead of default)
		renderContext.setEdgeDrawPaintFunction(
			e -> renderContext.getSelectedEdgeState().isSelected(e) ? Color.red
					: Colors.getColor(e));
		vv.setToolTipText("");

		// assign the shapes to the modal renderer
		ModalRenderer<AttributedVertex, AttributedEdge> modalRenderer = vv.getRenderer();
		// the modal renderer optimizes rendering for large graphs by removing detail

		Renderer.Vertex<AttributedVertex, AttributedEdge> vertexRenderer =
			modalRenderer.getVertexRenderer(LIGHTWEIGHT);
		// cause the lightweight (optimized) renderer to use the vertex shapes instead
		// of using default shapes.
		if (vertexRenderer instanceof LightweightVertexRenderer) {
			LightweightVertexRenderer<AttributedVertex, AttributedEdge> lightweightVertexRenderer =
				(LightweightVertexRenderer<AttributedVertex, AttributedEdge>) vertexRenderer;
			lightweightVertexRenderer.setVertexShapeFunction(ProgramGraphFunctions::getVertexShape);
		}

		renderContext.setVertexLabelRenderer(new JLabelVertexLabelRenderer(Color.black));
		renderContext.setVertexDrawPaintFunction(Colors::getColor);
		renderContext.setVertexFillPaintFunction(Colors::getColor);
		renderContext.setVertexStrokeFunction(n -> new BasicStroke(3.0f));

		renderContext.setEdgeShapeFunction(EdgeShape.line());

		DefaultGraphMouse<AttributedVertex, AttributedEdge> graphMouse = new DefaultGraphMouse<>();
		vv.setGraphMouse(graphMouse);
		vv.getComponent().requestFocus();
		vv.setBackground(Color.WHITE);
		return vv;
	}

	/**
	 * a way to sort attributed vertices or edges based on attribute values
	 */
}
