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

import static org.jungrapht.visualization.MultiLayerTransformer.Layer.*;
import static org.jungrapht.visualization.renderers.BiModalRenderer.*;

import java.awt.*;
import java.awt.event.*;
import java.awt.geom.Point2D;
import java.util.*;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.event.AncestorEvent;
import javax.swing.event.AncestorListener;

import org.jgrapht.Graph;
import org.jgrapht.graph.AsSubgraph;
import org.jungrapht.visualization.*;
import org.jungrapht.visualization.annotations.MultiSelectedVertexPaintable;
import org.jungrapht.visualization.annotations.SingleSelectedVertexPaintable;
import org.jungrapht.visualization.control.*;
import org.jungrapht.visualization.decorators.*;
import org.jungrapht.visualization.layout.algorithms.LayoutAlgorithm;
import org.jungrapht.visualization.layout.algorithms.util.InitialDimensionFunction;
import org.jungrapht.visualization.layout.model.LayoutModel;
import org.jungrapht.visualization.layout.model.Point;
import org.jungrapht.visualization.renderers.*;
import org.jungrapht.visualization.renderers.Renderer;
import org.jungrapht.visualization.selection.MutableSelectedState;
import org.jungrapht.visualization.selection.VertexEndpointsSelectedEdgeSelectedState;
import org.jungrapht.visualization.transform.*;
import org.jungrapht.visualization.transform.shape.MagnifyImageLensSupport;
import org.jungrapht.visualization.transform.shape.MagnifyShapeTransformer;
import org.jungrapht.visualization.util.RectangleUtils;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.action.builder.*;
import docking.menu.ActionState;
import docking.widgets.EventTrigger;
import ghidra.framework.plugintool.PluginTool;
import ghidra.graph.AttributeFilters;
import ghidra.graph.job.GraphJobRunner;
import ghidra.service.graph.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

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
	 * the "owner name" for action - mainly affects default help location
	 */
	private final String actionOwnerName = "GraphServices";

	/**
	 * provides the component for the {@link GraphDisplay}
	 */
	private final DefaultGraphDisplayComponentProvider componentProvider;

	/**
	 * whether to ensure the focused vertex is visible, scrolling if necessary
	 * the visualization in order to center the selected vertex
	 * or the center of the set of selected vertices
	 */
	private boolean ensureVertexIsVisible = false;

	/**
	 * allows selection of various {@link LayoutAlgorithm} ('arrangements')
	 */
	private final LayoutTransitionManager layoutTransitionManager;

	/**
	 * provides graph displays for supplied graphs
	 */
	private final DefaultGraphDisplayProvider graphDisplayProvider;
	/**
	 *  a 'busy' dialog to show while the layout algorithm is working
	 */
	private LayoutWorkingDialog layoutWorkingDialog;
	/**
	 * the vertex that has been nominated to be 'focused' in the graph display and listing
	 */
	private AttributedVertex focusedVertex;
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
	 * Handles the popup
	 */
	private GhidraGraphMouse graphMouse;

	/**
	 * Will accept a {@link Graph} and use it to create a new graph display in
	 * a new tab or new window
	 */
	Consumer<Graph<AttributedVertex, AttributedEdge>> subgraphConsumer = g -> {
		try {
			AttributedGraph attributedGraph = new AttributedGraph();
			g.vertexSet().forEach(attributedGraph::addVertex);
			g.edgeSet().forEach(e -> {
				AttributedVertex source = g.getEdgeSource(e);
				AttributedVertex target = g.getEdgeTarget(e);
				attributedGraph.addEdge(source, target, e);
			});
			displaySubGraph(attributedGraph);
		}
		catch (CancelledException e) {
			// noop
		}
	};
	private ToggleDockingAction hideSelectedAction;
	private ToggleDockingAction hideUnselectedAction;
	private SwitchableSelectionItemListener switchableSelectionListener;

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
			new LayoutTransitionManager(viewer, this::isRoot);

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
				.builder(viewer.getRenderContext().getVertexBoundsFunction())
				.build());

		graphMouse = new GhidraGraphMouse(componentProvider, viewer);

		createToolbarActions();
		createPopupActions();
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
	 * create the highlighters ({@code Paintable}s to show which vertices have been selected or focused)
	 */
	private void buildHighlighers() {
		// for highlighting of multiple selected vertices
		MultiSelectedVertexPaintable<AttributedVertex, AttributedEdge> multiSelectedVertexPaintable =
			MultiSelectedVertexPaintable.builder(viewer)
					.selectionStrokeMin(4.f)
					.selectionPaint(Color.red)
					.useBounds(false)
					.build();

		// manages highlight painting of a single selected vertex
		SingleSelectedVertexPaintable<AttributedVertex, AttributedEdge> singleSelectedVertexPaintable =
			SingleSelectedVertexPaintable.builder(viewer)
					.selectionStrokeMin(4.f)
					.selectionPaint(Color.red)
					.selectedVertexFunction(vs -> this.focusedVertex)
					.build();

		// draws the selection highlights
		viewer.addPostRenderPaintable(multiSelectedVertexPaintable);

		// draws the location arrow
		viewer.addPostRenderPaintable(singleSelectedVertexPaintable);

	}

	/**
	 * create the action icon buttons on the upper-right of the graph display window
	 */
	private void createToolbarActions() {

		// create a toggle for 'scroll to selected vertex'
		new ToggleActionBuilder("Scroll To Selection", actionOwnerName)
				.toolBarIcon(Icons.NAVIGATE_ON_INCOMING_EVENT_ICON)
				.description("Ensure that the 'focused' vertex is visible")
				.selected(true)
				.onAction(context -> ensureVertexIsVisible =
					((AbstractButton) context.getSourceObject()).isSelected())
				.buildAndInstallLocal(componentProvider);

		this.ensureVertexIsVisible = true;  // since we intialized action to selected

		// create a toggle for enabling 'free-form' selection: selection is
		// inside of a traced shape instead of a rectangle
		new ToggleActionBuilder("Free-Form Selection", actionOwnerName)
				.toolBarIcon(DefaultDisplayGraphIcons.LASSO_ICON)
				.description("Trace Free-Form Shape to select multiple vertices (CTRL-click-drag)")
				.selected(false)
				.onAction(context -> freeFormSelection =
					((AbstractButton) context.getSourceObject()).isSelected())
				.buildAndInstallLocal(componentProvider);

		// create an icon button to display the satellite view
		new ToggleActionBuilder("SatelliteView", actionOwnerName).description("Show Satellite View")
				.toolBarIcon(DefaultDisplayGraphIcons.SATELLITE_VIEW_ICON)
				.onAction(this::toggleSatellite)
				.buildAndInstallLocal(componentProvider);

		// create an icon button to reset the view transformations to identity (scaled to layout)
		new ActionBuilder("Reset View", actionOwnerName)
				.description("Reset all view transforms to center graph in display")
				.toolBarIcon(Icons.REFRESH_ICON)
				.onAction(context -> viewer.scaleToLayout())
				.buildAndInstallLocal(componentProvider);

		// create a button to show the view magnify lens
		LensSupport<LensGraphMouse> magnifyViewSupport = createMagnifier();
		ToggleDockingAction lensToggle = new ToggleActionBuilder("View Magnifier", actionOwnerName)
				.description("Show View Magnifier")
				.toolBarIcon(DefaultDisplayGraphIcons.VIEW_MAGNIFIER_ICON)
				.onAction(context -> magnifyViewSupport.activate(
					((AbstractButton) context.getSourceObject()).isSelected()))
				.build();
		magnifyViewSupport.addItemListener(
			itemEvent -> lensToggle.setSelected(itemEvent.getStateChange() == ItemEvent.SELECTED));
		componentProvider.addLocalAction(lensToggle);

		// create an action button to show a dialog with generated filters
		new ActionBuilder("Show Filters", actionOwnerName).description("Show Graph Filters")
				.toolBarIcon(DefaultDisplayGraphIcons.FILTER_ICON)
				.onAction(context -> showFilterDialog())
				.buildAndInstallLocal(componentProvider);

		// create a menu with graph layout algorithm selections
		new MultiStateActionBuilder<String>("Arrangement", actionOwnerName)
				.description("Select Layout Arrangement Algorithm")
				.toolBarIcon(DefaultDisplayGraphIcons.LAYOUT_ALGORITHM_ICON)
				.fireFirstAction(false)
				.onActionStateChanged((s, t) -> layoutChanged(s.getName()))
				.addStates(getLayoutActionStates())
				.buildAndInstallLocal(componentProvider);

		// show a 'busy' dialog while the layout algorithm is computing vertex locations
		viewer.getVisualizationModel()
				.getLayoutModel()
				.getLayoutStateChangeSupport()
				.addLayoutStateChangeListener(
					evt -> {
						if (evt.active) {
							Swing.runLater(this::showLayoutWorking);
						}
						else {
							Swing.runLater(this::hideLayoutWorking);
						}
					});
	}

	private void createPopupActions() {
		new ActionBuilder("Select Vertex", actionOwnerName)
				.popupMenuPath("Select Vertex")
				.popupMenuGroup("selection", "1")
				.withContext(VertexGraphActionContext.class)
				.enabledWhen(c -> !viewer.getSelectedVertexState().isSelected(c.getClickedVertex()))
				.onAction(c -> viewer.getSelectedVertexState().select(c.getClickedVertex()))
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Deselect Vertex", actionOwnerName)
				.popupMenuPath("Deselect Vertex")
				.popupMenuGroup("selection", "2")
				.withContext(VertexGraphActionContext.class)
				.enabledWhen(c -> viewer.getSelectedVertexState().isSelected(c.getClickedVertex()))
				.onAction(c -> viewer.getSelectedVertexState().deselect(c.getClickedVertex()))
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Select Edge", actionOwnerName)
				.popupMenuPath("Select Edge")
				.popupMenuGroup("selection", "1")
				.withContext(EdgeGraphActionContext.class)
				.enabledWhen(c -> !viewer.getSelectedEdgeState().isSelected(c.getClickedEdge()))
				.onAction(c -> selectEdge(c.getClickedEdge()))
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Deselect Edge", actionOwnerName)
				.popupMenuPath("Deselect Edge")
				.popupMenuGroup("selection", "2")
				.withContext(EdgeGraphActionContext.class)
				.enabledWhen(c -> viewer.getSelectedEdgeState().isSelected(c.getClickedEdge()))
				.onAction(c -> deselectEdge(c.getClickedEdge()))
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Edge Source", actionOwnerName)
				.popupMenuPath("Go To Edge Source")
				.popupMenuGroup("Go To")
				.withContext(EdgeGraphActionContext.class)
				.onAction(c -> setFocusedVertex(graph.getEdgeSource(c.getClickedEdge())))
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Edge Target", actionOwnerName)
				.popupMenuPath("Go To Edge Target")
				.popupMenuGroup("Go To")
				.withContext(EdgeGraphActionContext.class)
				.onAction(c -> setFocusedVertex(graph.getEdgeTarget(c.getClickedEdge())))
				.buildAndInstallLocal(componentProvider);

		hideSelectedAction = new ToggleActionBuilder("Hide Selected", actionOwnerName)
				.popupMenuPath("Hide Selected")
				.popupMenuGroup("z", "1")
				.description("Toggles whether or not to show selected vertices and edges")
				.onAction(c -> manageVertexDisplay())
				.buildAndInstallLocal(componentProvider);

		hideUnselectedAction = new ToggleActionBuilder("Hide Unselected", actionOwnerName)
				.popupMenuPath("Hide Unselected")
				.popupMenuGroup("z", "2")
				.description("Toggles whether or not to show selected vertices and edges")
				.onAction(c -> manageVertexDisplay())
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Invert Selection", actionOwnerName)
				.popupMenuPath("Invert Selection")
				.popupMenuGroup("z", "3")
				.description("Inverts the current selection")
				.onAction(c -> invertSelection())
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Grow Selection To Targets", actionOwnerName)
				.popupMenuPath("Grow Selection To Targets")
				.popupMenuGroup("z", "4")
				.description("Extends the current selection by including the target vertex " +
					"of all edges whose source is selected")
				.keyBinding("ctrl O")
				.enabledWhen(c -> !isAllSelected(getTargetVerticesFromSelected()))
				.onAction(c -> growSelection(getTargetVerticesFromSelected()))
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Grow Selection From Sources", actionOwnerName)
				.popupMenuPath("Grow Selection From Sources")
				.popupMenuGroup("z", "4")
				.description("Extends the current selection by including the target vertex " +
					"of all edges whose source is selected")
				.keyBinding("ctrl I")
				.enabledWhen(c -> !isAllSelected(getSourceVerticesFromSelected()))
				.onAction(c -> growSelection(getSourceVerticesFromSelected()))
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Create Subgraph", actionOwnerName)
				.popupMenuPath("Display Selected as New Graph")
				.popupMenuGroup("z", "5")
				.description("Creates a subgraph from the selected nodes")
				.enabledWhen(c -> !viewer.getSelectedVertexState().getSelected().isEmpty())
				.onAction(c -> createAndDisplaySubGraph())
				.buildAndInstallLocal(componentProvider);
	}

	private void createAndDisplaySubGraph() {
		GraphDisplay display = graphDisplayProvider.getGraphDisplay(false, TaskMonitor.DUMMY);
		try {
			display.setGraph(createSubGraph(), "SubGraph", false, TaskMonitor.DUMMY);
			display.setGraphDisplayListener(listener.cloneWith(display));
		}
		catch (CancelledException e) {
			// using Dummy, so can't happen
		}
	}

	private AttributedGraph createSubGraph() {
		Set<AttributedVertex> selected = viewer.getSelectedVertexState().getSelected();
		Graph<AttributedVertex, AttributedEdge> subGraph = new AsSubgraph<>(graph, selected);

		AttributedGraph newGraph = new AttributedGraph();
		subGraph.vertexSet().forEach(newGraph::addVertex);
		subGraph.edgeSet().forEach(e -> {
			AttributedVertex source = subGraph.getEdgeSource(e);
			AttributedVertex target = subGraph.getEdgeTarget(e);
			newGraph.addEdge(source, target, e);
		});
		return newGraph;
	}

	private void growSelection(Set<AttributedVertex> vertices) {
		viewer.getSelectedVertexState().select(vertices);
	}

	private boolean isAllSelected(Set<AttributedVertex> vertices) {
		return viewer.getSelectedVertexState().getSelected().containsAll(vertices);
	}

	private Set<AttributedVertex> getTargetVerticesFromSelected() {
		Set<AttributedVertex> targets = new HashSet<>();
		Set<AttributedVertex> selectedVertices = getSelectedVertices();
		selectedVertices.forEach(v -> {
			Set<AttributedEdge> edges = graph.outgoingEdgesOf(v);
			edges.forEach(e -> targets.add(graph.getEdgeTarget(e)));
		});
		return targets;
	}

	private Set<AttributedVertex> getSourceVerticesFromSelected() {
		Set<AttributedVertex> sources = new HashSet<>();
		Set<AttributedVertex> selectedVertices = getSelectedVertices();
		selectedVertices.forEach(v -> {
			Set<AttributedEdge> edges = graph.incomingEdgesOf(v);
			edges.forEach(e -> sources.add(graph.getEdgeSource(e)));
		});
		return sources;
	}

	private void invertSelection() {
		switchableSelectionListener.setEnabled(false);
		try {
			MutableSelectedState<AttributedVertex> selectedVertexState =
				viewer.getSelectedVertexState();
			graph.vertexSet().forEach(v -> {
				if (selectedVertexState.isSelected(v)) {
					selectedVertexState.deselect(v);
				}
				else {
					selectedVertexState.select(v);
				}
			});
			Set<AttributedVertex> selected = selectedVertexState.getSelected();
			notifySelectionChanged(selected);
		}
		finally {
			switchableSelectionListener.setEnabled(true);
		}
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
			ActionState<String> state = new ActionState<>(layoutName,
				DefaultDisplayGraphIcons.LAYOUT_ALGORITHM_ICON, layoutName);
			state.setHelpLocation(new HelpLocation(actionOwnerName, layoutName));
			actionStates.add(state);
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

	private void displaySubGraph(Graph<AttributedVertex, AttributedEdge> subGraph)
			throws CancelledException {
		GraphDisplay graphDisplay = graphDisplayProvider.getGraphDisplay(false, TaskMonitor.DUMMY);
		graphDisplay.setGraph((AttributedGraph) subGraph, "SubGraph", false, TaskMonitor.DUMMY);
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
		final SatelliteVisualizationViewer<AttributedVertex, AttributedEdge> satellite =
			SatelliteVisualizationViewer.builder(parentViewer)
					.viewSize(satelliteSize)
					.build();
		satellite.setGraphMouse(new DefaultSatelliteGraphMouse());
		satellite.getRenderContext().setEdgeDrawPaintFunction(Colors::getColor);
		satellite.getRenderContext()
				.setEdgeStrokeFunction(ProgramGraphFunctions::getEdgeStroke);
		satellite.getRenderContext().setVertexFillPaintFunction(Colors::getColor);
		satellite.scaleToLayout();
		satellite.getRenderContext().setVertexLabelFunction(n -> null);
		satellite.getComponent().setBorder(BorderFactory.createEtchedBorder());
		parentViewer.getComponent().addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent evt) {
				Dimension size = evt.getComponent().getSize();
				Dimension quarterSize = new Dimension(size.width / 4, size.height / 4);
				satellite.getComponent().setSize(quarterSize);
			}
		});
		return satellite;
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
		componentProvider.closeComponent();
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
		viewer.setGraphMouse(graphMouse);
	}

	private void deselectEdge(AttributedEdge edge) {
		viewer.getSelectedEdgeState().deselect(edge);
		AttributedVertex source = graph.getEdgeSource(edge);
		AttributedVertex target = graph.getEdgeTarget(edge);
		viewer.getSelectedVertexState().deselect(Set.of(source, target));
	}

	private void selectEdge(AttributedEdge edge) {
		viewer.getSelectedEdgeState().select(edge);
		AttributedVertex source = graph.getEdgeSource(edge);
		AttributedVertex target = graph.getEdgeTarget(edge);
		viewer.getSelectedVertexState().select(Set.of(source, target));
	}

	/**
	 * connect the selection state to to the visualization
	 */
	private void connectSelectionStateListeners() {
		switchableSelectionListener = new SwitchableSelectionItemListener();
		viewer.getSelectedVertexState().addItemListener(switchableSelectionListener);
	}

	protected void setFocusedVertex(AttributedVertex vertex) {
		setFocusedVertex(vertex, EventTrigger.API_CALL);
	}

	@Override
	public void setFocusedVertex(AttributedVertex vertex, EventTrigger eventTrigger) {
		boolean changed = this.focusedVertex != vertex;
		this.focusedVertex = vertex;
		if (focusedVertex != null) {
			if (changed && eventTrigger != EventTrigger.INTERNAL_ONLY) {
				notifyLocationFocusChanged(focusedVertex);
			}
			// make sure the vertex is visible, even if the vertex has not changed
			scrollToSelected(focusedVertex);
		}
		viewer.repaint();
	}

	/**
	 * determines whether the passed layout coordinates are visible in the display
	 * @param x of interest (layout coordinates)
	 * @param y of interest (layout coordinates)
	 * @return {@code true} if the coordinates are visible in the display view
	 */
	private boolean isVisible(double x, double y) {
		if (viewer.getComponent().isVisible() && !viewer.getBounds().isEmpty()) {
			// project the view bounds into the layout coordinate system, test for containing the coordinates
			return viewer.getRenderContext()
					.getMultiLayerTransformer()
					.inverseTransform(viewer.getBounds())
					.getBounds()
					.contains(x, y);
		}
		return true;
	}

	/**
	 * transform the supplied {@code AttributedVertex}s to a List of their ids
	 * @param selectedVertices the collections of vertices.
	 * @return a list of vertex ids
	 */
	private List<String> toVertexIds(Collection<AttributedVertex> selectedVertices) {
		return selectedVertices.stream().map(AttributedVertex::getId).collect(Collectors.toList());
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

	/**
	 * fire an event to notify the selected vertices changed
	 * @param selected the list of selected vertices
	 */
	private void notifySelectionChanged(Set<AttributedVertex> selected) {
		Swing.runLater(() -> listener.selectionChanged(selected));
	}

	/**
	 * fire and event to say the focused vertex changed
	 * @param vertex the new focused vertex
	 */
	private void notifyLocationFocusChanged(AttributedVertex vertex) {
		Swing.runLater(() -> listener.locationFocusChanged(vertex));
	}

	@Override
	public void selectVertices(Set<AttributedVertex> selected, EventTrigger eventTrigger) {
		// if we are not to fire events, turn off the selection listener we provided to the
		// graphing library.
		switchableSelectionListener.setEnabled(eventTrigger != EventTrigger.INTERNAL_ONLY);

		try {
			MutableSelectedState<AttributedVertex> nodeSelectedState =
				viewer.getSelectedVertexState();
			if (selected.isEmpty()) {
				nodeSelectedState.clear();
			}
			else if (!Arrays.asList(nodeSelectedState.getSelectedObjects()).containsAll(selected)) {
				nodeSelectedState.clear();
				nodeSelectedState.select(selected, false);
				scrollToSelected(selected);
			}
			viewer.repaint();
		}
		finally {
			// always turn on the selection listener
			switchableSelectionListener.setEnabled(true);
		}
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

		Swing.runNow(() -> {
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
		if (ensureVertexIsVisible) {
			jobRunner.finishAllJobs();

			Point2D newCenter = getPointToCenter(vertices);
			if (!isVisible(newCenter.getX(), newCenter.getY())) {
				Point2D existingCenter = viewer.getRenderContext()
						.getMultiLayerTransformer()
						.inverseTransform(viewer.getCenter());
				jobRunner.schedule(new CenterAnimationJob(viewer, existingCenter, newCenter));
			}
		}
	}

	/**
	 * scroll the visualization to center the passed vertex
	 * @param vertex the vertex to center
	 */
	private void scrollToSelected(AttributedVertex vertex) {
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
	 * @param vertex the vertex to update
	 * @param newName the new name of the vertex
	 */
	@Override
	public void updateVertexName(AttributedVertex vertex, String newName) {
		vertex.setName(newName);
		vertex.clearCache();
		iconCache.evict(vertex);
		viewer.repaint();
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
	 * @return the new VisualizationViewer
	 */
	public VisualizationViewer<AttributedVertex, AttributedEdge> createViewer() {
		final VisualizationViewer<AttributedVertex, AttributedEdge> vv =
			VisualizationViewer.<AttributedVertex, AttributedEdge> builder()
					.multiSelectionStrategySupplier(
						() -> freeFormSelection ? MultiSelectionStrategy.arbitrary()
								: MultiSelectionStrategy.rectangular())
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
				// do nothing
			}

			@Override
			public void ancestorMoved(AncestorEvent ancestorEvent) {
				// do nothing
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
				.builder(
					nodeImageShapeFunction.andThen(s -> RectangleUtils.convert(s.getBounds2D())))
				.build());

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
		MouseListener[] mouseListeners = vv.getComponent().getMouseListeners();
		for (MouseListener mouseListener : mouseListeners) {
			vv.getComponent().removeMouseListener(mouseListener);
		}

		return vv;
	}

	/**
	 * Item listener for selection changes in the graph with the additional 
	 * capability of being able to disable the listener without removing it. 
	 */
	class SwitchableSelectionItemListener implements ItemListener {
		boolean enabled = true;

		@Override
		public void itemStateChanged(ItemEvent e) {
			if (enabled) {
				Swing.runLater(() -> run(e));
			}
		}

		private void run(ItemEvent e) {
			// there was a change in the set of selected vertices.
			// if the focused vertex is null, set it from one of the selected
			// vertices
			if (e.getStateChange() == ItemEvent.SELECTED) {
				Collection<AttributedVertex> selectedVertices = getVertices(e.getItem());
				notifySelectionChanged(new HashSet<AttributedVertex>(selectedVertices));

				if (selectedVertices.size() == 1) {
					// if only one vertex was selected, make it the focused vertex
					setFocusedVertex(selectedVertices.stream().findFirst().get());
				}
				else if (DefaultGraphDisplay.this.focusedVertex == null) {
					// if there is currently no focused Vertex, attempt to get
					// one from the selectedVertices
					setFocusedVertex(selectedVertices.stream().findFirst().orElse(null));
				}
			}
			else if (e.getStateChange() == ItemEvent.DESELECTED) {
				notifySelectionChanged(Collections.emptySet());
			}
			viewer.repaint();
		}

		void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}
	}

	@Override
	public void addAction(DockingAction action) {
		componentProvider.addLocalAction(action);
	}

	@Override
	public AttributedVertex getFocusedVertex() {
		return focusedVertex;
	}

	@Override
	public Set<AttributedVertex> getSelectedVertices() {
		return viewer.getSelectedVertexState().getSelected();
	}

	public ActionContext getActionContext(MouseEvent e) {

		AttributedVertex pickedVertex = graphMouse.getPickedVertex(e);
		if (pickedVertex != null) {
			return new VertexGraphActionContext(componentProvider, graph, getSelectedVertices(),
				focusedVertex, pickedVertex);
		}

		AttributedEdge pickedEdge = graphMouse.getPickedEdge(e);
		if (pickedEdge != null) {
			return new EdgeGraphActionContext(componentProvider, graph, getSelectedVertices(),
				focusedVertex, pickedEdge);
		}

		return new GraphActionContext(componentProvider, graph, getSelectedVertices(),
			focusedVertex);

	}


	/**
	 * Use the hide selected action states to determine what vertices are shown:
	 * <ul>
	 *     <li>unselected vertices only</li>
	 *     <li>selected vertices only</li>
	 *     <li>both selected and unselected vertices are shown</li>
	 *     <li>neither selected nor unselected vertices are shown</li>
	 * </ul>
	 */
	private void manageVertexDisplay() {
		boolean hideSelected = hideSelectedAction.isSelected();
		boolean hideUnselected = hideUnselectedAction.isSelected();
		MutableSelectedState<AttributedVertex> selectedVertexState =
			viewer.getSelectedVertexState();
		if (hideSelected && hideUnselected) {
			viewer.getRenderContext()
					.setVertexIncludePredicate(v -> false);
		}
		else if (hideSelected) {
			viewer.getRenderContext()
					.setVertexIncludePredicate(Predicate.not(selectedVertexState::isSelected));
		}
		else if (hideUnselected) {
			viewer.getRenderContext()
					.setVertexIncludePredicate(selectedVertexState::isSelected);
		}
		else {
			viewer.getRenderContext()
					.setVertexIncludePredicate(v -> true);
		}
		viewer.repaint();
	}

	@Override
	public AttributedGraph getGraph() {
		return graph;
	}
}
