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

import docking.ActionContext;
import docking.action.ToggleDockingAction;
import docking.action.builder.ActionBuilder;
import docking.action.builder.MultiStateActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import docking.menu.ActionState;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.graph.AttributeFilters;
import ghidra.graph.job.GraphJobRunner;
import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.AttributedVertex;
import ghidra.service.graph.DummyGraphDisplayListener;
import ghidra.service.graph.GraphDisplay;
import ghidra.service.graph.GraphDisplayListener;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import org.jgrapht.Graph;
import org.jungrapht.visualization.RenderContext;
import org.jungrapht.visualization.SatelliteVisualizationViewer;
import org.jungrapht.visualization.VisualizationViewer;
import org.jungrapht.visualization.annotations.MultiSelectedVertexPaintable;
import org.jungrapht.visualization.annotations.SingleSelectedVertexPaintable;
import org.jungrapht.visualization.control.DefaultGraphMouse;
import org.jungrapht.visualization.control.DefaultLensGraphMouse;
import org.jungrapht.visualization.control.DefaultSatelliteGraphMouse;
import org.jungrapht.visualization.control.LensGraphMouse;
import org.jungrapht.visualization.control.LensMagnificationGraphMousePlugin;
import org.jungrapht.visualization.control.MultiSelectionStrategy;
import org.jungrapht.visualization.decorators.EdgeShape;
import org.jungrapht.visualization.decorators.EllipseShapeFunction;
import org.jungrapht.visualization.decorators.IconShapeFunction;
import org.jungrapht.visualization.layout.algorithms.LayoutAlgorithm;
import org.jungrapht.visualization.layout.algorithms.util.InitialDimensionFunction;
import org.jungrapht.visualization.layout.model.LayoutModel;
import org.jungrapht.visualization.layout.model.Point;
import org.jungrapht.visualization.renderers.JLabelVertexLabelRenderer;
import org.jungrapht.visualization.renderers.LightweightVertexRenderer;
import org.jungrapht.visualization.renderers.ModalRenderer;
import org.jungrapht.visualization.renderers.Renderer;
import org.jungrapht.visualization.selection.MutableSelectedState;
import org.jungrapht.visualization.selection.VertexEndpointsSelectedEdgeSelectedState;
import org.jungrapht.visualization.transform.Lens;
import org.jungrapht.visualization.transform.LensSupport;
import org.jungrapht.visualization.transform.MutableTransformer;
import org.jungrapht.visualization.transform.shape.MagnifyImageLensSupport;
import org.jungrapht.visualization.transform.shape.MagnifyShapeTransformer;
import org.jungrapht.visualization.util.RectangleUtils;
import resources.Icons;

import javax.swing.AbstractButton;
import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JRadioButton;
import javax.swing.event.AncestorEvent;
import javax.swing.event.AncestorListener;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.ItemEvent;
import java.awt.geom.Point2D;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static org.jungrapht.visualization.MultiLayerTransformer.Layer.*;
import static org.jungrapht.visualization.renderers.BiModalRenderer.LIGHTWEIGHT;

/**
 * Delegates to a {@link VisualizationViewer} to draw a graph visualization
 */
public class DefaultGraphDisplay implements GraphDisplay {

	public static final String FAVORED_EDGE = "Fall-Through";
	private static final int MAX_NODES = Integer.getInteger("maxNodes", 10000);
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
	private final VisualizationViewer<AttributedVertex, AttributedEdge> viewer;

	/**
	 * the {@link PluginTool}
	 */
	private final PluginTool pluginTool;

	/**
	 * the {@link Plugin} that manages this {@link GraphDisplay}
	 */
	private final String pluginName = "ProgramGraphPlugin";

	/**
	 * provides the component for the {@link GraphDisplay}
	 */
	private final DefaultGraphDisplayComponentProvider componentProvider;

	/**
	 * whether to scroll the visualization in order to center the selected vertex
	 * (or the centroid of the selected vertices)
	 */
	private boolean enableScrollToSelection = false;

	/**
	 * allows selection of various {@link LayoutAlgorithm} ('arrangements')
	 */
	private final LayoutTransitionManager<AttributedVertex, AttributedEdge> layoutTransitionManager;

	/**
	 * provides graph displays for supplied graphs
	 */
	private final DefaultGraphDisplayProvider graphDisplayProvider;
	/**
	 *  a 'busy' dialog to show while the layout algorithm is working
	 */
	private LayoutWorkingDialog layoutWorkingDialog;
	/**
	 * the vertex that has been nominated to be 'located' in the graph display and listing
	 */
	private AttributedVertex locatedVertex;
	private final GraphJobRunner jobRunner = new GraphJobRunner();
	/**
	 * a satellite view that shows in the lower left corner as a birds-eye view of the graph display
	 */
	private final SatelliteVisualizationViewer<AttributedVertex, AttributedEdge> satelliteViewer;
	/**
	 * generated filters on edges
	 */
	private AttributeFilters edgeFilters;
	/**
	 * generated filters on vertices
	 */
	private AttributeFilters vertexFilters;
	/**
	 * a dialog populated with generated vertex/edge filters
	 */
	private FilterDialog filterDialog;
	/**
	 * holds the vertex icons (instead of recomputing them)
	 */
	private GhidraIconCache iconCache;
	/**
	 * multi-selection is done in a free-form traced shape instead of a rectangle
	 */
	private boolean freeFormSelection;

	/**
	 * Will accept a {@link Graph} and use it to create a new graph display in
	 * a new tab or new window
	 */
	Consumer<Graph<AttributedVertex, AttributedEdge>> subgraphConsumer =
			g -> {
				try {
					AttributedGraph attributedGraph = new AttributedGraph();
					g.vertexSet().forEach(attributedGraph::addVertex);
					g.edgeSet().forEach(e -> {
						AttributedVertex source = g.getEdgeSource(e);
						AttributedVertex target = g.getEdgeTarget(e);
						attributedGraph.addEdge(source, target, e);
					});
					displaySubGraph(attributedGraph);
				} catch (CancelledException e) {
					// noop
				}
			};

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
			new LayoutTransitionManager<>(viewer, this::isRoot);

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

		viewer.setInitialDimensionFunction(InitialDimensionFunction
				.builder(viewer.getRenderContext().getVertexBoundsFunction()).build());

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

	/**
	 * create a magnification lens for the graph display
	 * @return a {@link LensSupport} for the new magnifier
	 */
	private LensSupport<LensGraphMouse> createMagnifier() {
		Lens lens = Lens.builder().lensShape(Lens.Shape.RECTANGLE).magnification(3.f).build();
		lens.setMagnification(2.f);
		LensMagnificationGraphMousePlugin magnificationPlugin =
			new LensMagnificationGraphMousePlugin(1.f, 60.f, .2f);

		MutableTransformer transformer = viewer.getRenderContext()
				.getMultiLayerTransformer()
				.getTransformer(VIEW);

		MagnifyShapeTransformer shapeTransformer = MagnifyShapeTransformer.builder(lens)
				// this lens' delegate is the viewer's VIEW layer
				.delegate(transformer)
				.build();
		LensGraphMouse lensGraphMouse = new DefaultLensGraphMouse<>(magnificationPlugin);
		return MagnifyImageLensSupport.builder(viewer)
				.lensTransformer(shapeTransformer)
				.lensGraphMouse(lensGraphMouse)
				.build();
	}

	/**
	 * create the highlighters ({@code Paintable}s to show which vertices have been selected or located
	 */
	private void buildHighlighers() {
		// for highlighting of multiple selected vertices
		MultiSelectedVertexPaintable<AttributedVertex, AttributedEdge> multiSelectedVertexPaintable = MultiSelectedVertexPaintable.builder(viewer)
				.selectionStrokeMin(4.f)
				.selectionPaint(Color.red)
				.useBounds(false)
				.build();


		// manages highlight painting of a single selected vertex
		SingleSelectedVertexPaintable<AttributedVertex, AttributedEdge> singleSelectedVertexPaintable = SingleSelectedVertexPaintable.builder(viewer)
				.selectionStrokeMin(4.f)
				.selectionPaint(Color.red)
				.selectedVertexFunction(vs -> this.locatedVertex)
				.build();

		// draws the selection highlights
		viewer.addPostRenderPaintable(multiSelectedVertexPaintable);

		// draws the location arrow
		viewer.addPostRenderPaintable(singleSelectedVertexPaintable);

	}

	/**
	 * create the action icon buttons on the upper-right of the graph display window
	 */
	private void createActions() {

		// create a toggle for 'scroll to selected vertex'
		new ToggleActionBuilder("Scroll To Selection", pluginName)
				.toolBarIcon(Icons.NAVIGATE_ON_INCOMING_EVENT_ICON)
				.description("Scroll display to center the 'Located' vertex")
				.selected(false)
				.onAction(context -> enableScrollToSelection =
					((AbstractButton) context.getSourceObject()).isSelected())
				.buildAndInstallLocal(componentProvider);

		// create a toggle for enabling 'free-form' selection: selection is
		// inside of a traced shape instead of a rectangle
		new ToggleActionBuilder("Free-Form Selection", pluginName)
				.toolBarIcon(DefaultDisplayGraphIcons.LASSO_ICON)
				.description("Trace Free-Form Shape to select multiple vertices (CTRL-click-drag)")
				.selected(false)
				.onAction(context ->
					freeFormSelection = ((AbstractButton) context.getSourceObject()).isSelected())
				.buildAndInstallLocal(componentProvider);


		// create an icon button to display the satellite view
		new ToggleActionBuilder("SatelliteView", pluginName).description("Show Satellite View")
				.toolBarIcon(DefaultDisplayGraphIcons.SATELLITE_VIEW_ICON)
				.onAction(this::toggleSatellite)
				.buildAndInstallLocal(componentProvider);

		// create an icon button to reset the view transformations to identity (scaled to layout)
		new ActionBuilder("Reset View", pluginName)
				.description("Reset all view transforms to center graph in display")
				.toolBarIcon(Icons.REFRESH_ICON)
				.onAction(context -> viewer.scaleToLayout())
				.buildAndInstallLocal(componentProvider);

		// create a button to show the view magnify lens
		LensSupport<LensGraphMouse> magnifyViewSupport = createMagnifier();
		ToggleDockingAction lensToggle = new ToggleActionBuilder("View Magnifier", pluginName)
				.description("Show View Magnifier")
				.toolBarIcon(DefaultDisplayGraphIcons.VIEW_MAGNIFIER_ICON)
				.onAction(context -> magnifyViewSupport.activate(
						((AbstractButton) context.getSourceObject()).isSelected()
				))
				.build();
		magnifyViewSupport.addItemListener(itemEvent ->
				lensToggle.setSelected(itemEvent.getStateChange() == ItemEvent.SELECTED));
		componentProvider.addLocalAction(lensToggle);

		// create an action button to show a dialog with generated filters
		new ActionBuilder("Show Filters", pluginName).description("Show Graph Filters")
				.toolBarIcon(DefaultDisplayGraphIcons.FILTER_ICON)
				.onAction(context -> showFilterDialog())
				.buildAndInstallLocal(componentProvider);

		// create a menu with graph layout algorithm selections
		new MultiStateActionBuilder<String>("Arrangement", pluginName)
				.description("Select Layout Arrangement Algorithm")
				.toolBarIcon(DefaultDisplayGraphIcons.LAYOUT_ALGORITHM_ICON)
				.fireFirstAction(false)
				.onActionStateChanged((s, t) -> layoutChanged(s.getName()))
				.addStates(getLayoutActionStates())
				.buildAndInstallLocal(componentProvider);

		// show a 'busy' dialog while the layout algorithm is computing vertex locations
		viewer.getVisualizationModel().getLayoutModel()
				.getLayoutStateChangeSupport().addLayoutStateChangeListener(
				evt -> {
					if (evt.active) {
						Swing.runLater(this::showLayoutWorking);
					} else {
						Swing.runLater(this::hideLayoutWorking);
					}
				}
		);
	}

	/**
	 * get a {@code List} of {@code ActionState} buttons for the
	 * configured layout algorithms
	 * @return a {@code List} of {@code ActionState} buttons
	 */
	private List<ActionState<String>> getLayoutActionStates() {
		String[] names = layoutTransitionManager.getLayoutNames();
		List<ActionState<String>> actionStates = new ArrayList<>();
		for (String layoutName : names) {
			actionStates.add(new ActionState<>(layoutName,
				DefaultDisplayGraphIcons.LAYOUT_ALGORITHM_ICON, layoutName));
		}
		return actionStates;
	}

	/**
	 * respond to a change in the layout name
	 * @param layoutName the name of the layout algorithm to apply
	 */
	private void layoutChanged(String layoutName) {
		if (layoutTransitionManager != null) {
			layoutTransitionManager.setLayout(layoutName);
		}
	}

	/**
	 * show the dialog with generated filters
	 */
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

	/**
	 * show the 'busy' dialog indicating that the layout algorithm is working
	 */
	protected void showLayoutWorking() {
		if (this.layoutWorkingDialog != null) {
			layoutWorkingDialog.close();
		}
		this.layoutWorkingDialog =
				new LayoutWorkingDialog(viewer.getVisualizationModel().getLayoutAlgorithm());
		componentProvider.getTool().showDialog(layoutWorkingDialog);
	}

	/**
	 * hide the 'busy' dialog for the layout algorithm work
	 */
	protected void hideLayoutWorking() {
		if (this.layoutWorkingDialog != null) {
			layoutWorkingDialog.close();
		}
	}

	/**
	 * add or remove the satellite viewer
	 * @param context information about the event
	 */
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
	 * from the supplied {@link Graph}, create a new GraphDisplay in a new window or tab
	 * @param subGraph
	 * @throws CancelledException
	 */
	private void displaySubGraph(Graph<AttributedVertex, AttributedEdge> subGraph) throws CancelledException {
		GraphDisplay graphDisplay = graphDisplayProvider.getGraphDisplay(false, TaskMonitor.DUMMY);
		graphDisplay.setGraph((AttributedGraph)subGraph, "SubGraph", false, TaskMonitor.DUMMY);
		graphDisplay.setGraphDisplayListener(listener);
	}

	/**
	 * create a SatelliteViewer for the Visualization
	 * @param parentViewer the main visualization 'parent' of the satellite view
	 * @return a new SatelliteVisualizationViewer
	 */
	private SatelliteVisualizationViewer<AttributedVertex, AttributedEdge> createSatelliteViewer(
			VisualizationViewer<AttributedVertex, AttributedEdge> parentViewer) {
		Dimension viewerSize = parentViewer.getSize();
		Dimension satelliteSize = new Dimension(
				viewerSize.width / 4, viewerSize.height / 4);
		final SatelliteVisualizationViewer<AttributedVertex, AttributedEdge> satelliteViewer =
			SatelliteVisualizationViewer.builder(parentViewer)
					.viewSize(satelliteSize)
					.build();
		satelliteViewer.setGraphMouse(new DefaultSatelliteGraphMouse());
		satelliteViewer.getRenderContext().setEdgeDrawPaintFunction(Colors::getColor);
		satelliteViewer.getRenderContext()
				.setEdgeStrokeFunction(ProgramGraphFunctions::getEdgeStroke);
		satelliteViewer.getRenderContext().setVertexFillPaintFunction(Colors::getColor);
		satelliteViewer.scaleToLayout();
		satelliteViewer.getRenderContext().setVertexLabelFunction(n -> null);
		satelliteViewer.getComponent().setBorder(BorderFactory.createEtchedBorder());
		parentViewer.getComponent().addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent evt) {
				Dimension size = evt.getComponent().getSize();
				Dimension quarterSize = new Dimension(size.width / 4, size.height / 4);
				satelliteViewer.getComponent().setSize(quarterSize);
			}
		});
		return satelliteViewer;
	}

	/**
	 * close this graph display
	 */
	@Override
	public void close() {
		graphDisplayProvider.remove(this);
		if (listener != null) {
			listener.graphClosed();
		}
		listener = null;
	}

	/**
	 * accept a {@code GraphDisplayListener}
	 * @param listener the listener to be notified
	 */
	@Override
	public void setGraphDisplayListener(GraphDisplayListener listener) {
		if (this.listener != null) {
			this.listener.graphClosed();
		}
		this.listener = listener;
		DefaultGraphMouse<AttributedVertex, AttributedEdge> graphMouse =
				new GhidraGraphMouse<>(viewer,
						subgraphConsumer,
						listener,
						AttributedVertex::getId,
						AttributedVertex::getName);
		viewer.setGraphMouse(graphMouse);
	}

	/**
	 * connect the selection state to to the visualization
	 */
	private void connectSelectionStateListeners() {
		viewer.getSelectedVertexState().addItemListener(e -> Swing.runLater(() -> {
			// there was a change in the set of selected vertices.
			// if the locatedVertex is null, set it from one of the selected
			// vertices
			if (e.getStateChange() == ItemEvent.SELECTED) {
				Collection<AttributedVertex> selectedVertices = getVertices(e.getItem());
				List<String> selectedVertexIds = toVertexIds(selectedVertices);
				notifySelectionChanged(selectedVertexIds);

				if (selectedVertices.size() == 1) {
					// if only one vertex was selected, make it the locatedVertex
					setLocatedVertex(selectedVertices.stream().findFirst().get());
				} else if (this.locatedVertex == null) {
					// if there is currently no locatedVertex, attempt to get
					// one from the selectedVertices
					setLocatedVertex(selectedVertices.stream().findFirst().orElse(null));
				}
			}
			else if (e.getStateChange() == ItemEvent.DESELECTED) {
				notifySelectionChanged(Collections.emptyList());
			}
			viewer.repaint();
		}));
	}

	/**
	 * set the vertex that has been nominated to be 'located'
	 * @param vertex the lucky vertex
	 */
	protected void setLocatedVertex(AttributedVertex vertex) {
		boolean changed = this.locatedVertex != vertex;
		this.locatedVertex = vertex;
		if (locatedVertex != null && changed) {
			notifyLocationChanged(locatedVertex.getId());
		}
	}

	/**
	 * transform the supplied {@code AttributedVertex} Set members to a List of their ids
	 * @param selectedVertices
	 * @return
	 */
	private List<String> toVertexIds(Collection<AttributedVertex> selectedVertices) {
		return selectedVertices.stream().map(AttributedVertex::getId).collect(Collectors.toList());
	}

	private Collection<AttributedVertex> getVertices(Object item) {
		if (item instanceof Collection) {
			return (Collection<AttributedVertex>) item;
		}
		else if (item instanceof AttributedVertex) {
			return List.of((AttributedVertex) item);
		}
		return Collections.emptyList();
	}

	/**
	 * fire an event to say the selected vertices changed
	 * @param vertexIds
	 */
	private void notifySelectionChanged(List<String> vertexIds) {
		Swing.runLater(() -> listener.selectionChanged(vertexIds));
	}

	/**
	 * fire and event to say the located vertex changed
	 * @param vertexId
	 */
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

	/**
	 *
	 * @param vertexIds vertex ids of interest
	 * @return a {@code Set} containing the {@code AttributedVertex} for ths supplied ids
	 */
	private Set<AttributedVertex> getVertices(Collection<String> vertexIds) {
		Set<String> vertexSet = new HashSet<>(vertexIds);
		return graph.vertexSet()
				.stream()
				.filter(v -> vertexSet.contains(v.getId()))
				.collect(Collectors.toSet());
	}

	/**
	 * for the supplied vertex id, find the {@code AttributedVertex} and translate
	 * the display to center it
	 * @param vertexID the id of the vertex to focus
	 */
	@Override
	public void setLocation(String vertexID) {
		Optional<AttributedVertex> located =
			graph.vertexSet().stream().filter(v -> vertexID.equals(v.getId())).findFirst();
		log.fine("picking address:" + vertexID + " returned " + located);
		viewer.repaint();
		located.ifPresent(v -> {
			setLocatedVertex(v);
			scrollToSelected(v);
		});
		viewer.repaint();
	}

	/**
	 * set the {@link AttributedGraph} for visualization
	 * @param attributedGraph the {@link AttributedGraph} to visualize
	 */
	private void doSetGraphData(AttributedGraph attributedGraph) {
		graph = attributedGraph;

		layoutTransitionManager.setEdgeComparator(new EdgeComparator(graph, "EdgeType",
				DefaultGraphDisplay.FAVORED_EDGE));

		configureViewerPreferredSize();

		Swing.runNow(() ->  {
			// set the graph but defer the layoutalgorithm setting
			viewer.getVisualizationModel().setGraph(graph, false);
			configureFilters();
			LayoutAlgorithm<AttributedVertex> initialLayoutAlgorithm =
					layoutTransitionManager.getInitialLayoutAlgorithm();
			viewer.getVisualizationModel().setLayoutAlgorithm(initialLayoutAlgorithm);
		});
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
		return incomingEdgesOf.isEmpty();
	}

	/**
	 * configure filters for the graph, based on the vertex and edge attributes
	 */
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

	/**
	 * configure a preferred size based on the size of the graph to display
	 */
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

	/**
	 * consume a {@link Graph} and display it
	 * @param graph the graph to display or consume
	 * @param description a description of the graph
	 * @param append if true, append the new graph to any existing graph.
	 * @param monitor a {@link TaskMonitor} which can be used to cancel the graphing operation
	 */
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

	/**
	 * cause the graph to be centered and scaled nicely for the view window
	 */
	public void centerAndScale() {
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

		jobRunner.schedule(new CenterAnimation<>(viewer, existingCenter, newCenter));
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

	/**
	 * compute the centroid of a group of vertices, or the center of the graph display
	 * @param vertices a collection of vertices from which to compute the centroid from their locations
	 * @return the {@code Point2D} that is the center
	 */
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

	/**
	 * process a request to update the name attribute value of the vertex with the
	 * supplied id
	 * @param id the vertix id
	 * @param newName the new name of the vertex
	 */
	@Override
	public void updateVertexName(String id, String newName) {
		// find the vertex, if present, change the name
		Optional<AttributedVertex> optional = graph.vertexSet().stream()
				.filter(v -> v.getId().equals(id)).findFirst();
		if (optional.isPresent()) {
			AttributedVertex vertex = optional.get();
			vertex.setName(newName);
			vertex.clearCache();
			iconCache.evict(vertex);
			viewer.repaint();
		}
	}

	/**
	 *
	 * @return a description of this graph
	 */
	@Override
	public String getGraphDescription() {
		return description;
	}

	/**
	 * create and return a {@link VisualizationViewer} to display graphs
	 * @return
	 */
	public VisualizationViewer<AttributedVertex, AttributedEdge> createViewer() {
		final VisualizationViewer<AttributedVertex, AttributedEdge> vv =
			VisualizationViewer.<AttributedVertex, AttributedEdge> builder()
					.multiSelectionStrategySupplier(() -> freeFormSelection ?
							MultiSelectionStrategy.arbitrary() : MultiSelectionStrategy.rectangular())
					.viewSize(PREFERRED_VIEW_SIZE)
					.layoutSize(PREFERRED_LAYOUT_SIZE)
					.build();

		// Add an ancestor listener to scale and center the graph after the component
		// has been initially shown.
		vv.getComponent().addAncestorListener(new AncestorListener() {

			@Override
			public void ancestorAdded(AncestorEvent ancestorEvent) {
				vv.getComponent().removeAncestorListener(this);
				Swing.runLater(() -> {
					vv.scaleToLayout();
				});
			}

			@Override
			public void ancestorRemoved(AncestorEvent ancestorEvent) {

			}

			@Override
			public void ancestorMoved(AncestorEvent ancestorEvent) {

			}
		});

		this.iconCache = new GhidraIconCache();
		vv.setVertexToolTipFunction(AttributedVertex::getHtmlString);
		vv.setEdgeToolTipFunction(AttributedEdge::getHtmlString);
		RenderContext<AttributedVertex, AttributedEdge> renderContext = vv.getRenderContext();

		// set up the shape and color functions
		IconShapeFunction<AttributedVertex> nodeImageShapeFunction =
			new IconShapeFunction<>(new EllipseShapeFunction<>());

		vv.getRenderContext().setVertexIconFunction(iconCache::get);

		// cause the vertices to be drawn with custom icons/shapes
		nodeImageShapeFunction.setIconFunction(iconCache::get);
		renderContext.setVertexShapeFunction(nodeImageShapeFunction);
		renderContext.setVertexIconFunction(iconCache::get);

		vv.setInitialDimensionFunction(InitialDimensionFunction
				.builder(nodeImageShapeFunction.andThen(s -> RectangleUtils.convert(s.getBounds2D()))).build());

		// the selectedEdgeState will be controlled by the vertices that are selected.
		// if both endpoints of an edge are selected, select that edge.
		vv.setSelectedEdgeState(
				new VertexEndpointsSelectedEdgeSelectedState<>(vv.getVisualizationModel()::getGraph,
						vv.getSelectedVertexState()));

		// selected edges will be drawn with a wider stroke
		renderContext.setEdgeStrokeFunction(
			e -> renderContext.getSelectedEdgeState().isSelected(e) ? new BasicStroke(20.f)
					: ProgramGraphFunctions.getEdgeStroke(e));
		// selected edges will be drawn in red (instead of default)
		renderContext.setEdgeDrawPaintFunction(
			e -> renderContext.getSelectedEdgeState().isSelected(e) ? Color.red
					: Colors.getColor(e));
		renderContext.setArrowDrawPaintFunction(
				e -> renderContext.getSelectedEdgeState().isSelected(e) ? Color.red
						: Colors.getColor(e));
		renderContext.setArrowFillPaintFunction(
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

		vv.getComponent().requestFocus();
		vv.setBackground(Color.WHITE);
		return vv;
	}
}
