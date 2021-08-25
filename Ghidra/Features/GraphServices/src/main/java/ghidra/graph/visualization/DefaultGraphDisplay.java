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

import java.awt.*;
import java.awt.event.*;
import java.awt.geom.Point2D;
import java.util.*;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.event.*;

import org.jgrapht.Graph;
import org.jgrapht.graph.AsSubgraph;
import org.jungrapht.visualization.*;
import org.jungrapht.visualization.annotations.*;
import org.jungrapht.visualization.control.*;
import org.jungrapht.visualization.layout.algorithms.LayoutAlgorithm;
import org.jungrapht.visualization.layout.algorithms.util.InitialDimensionFunction;
import org.jungrapht.visualization.layout.model.LayoutModel;
import org.jungrapht.visualization.layout.model.Point;
import org.jungrapht.visualization.renderers.Renderer.VertexLabel.Position;
import org.jungrapht.visualization.selection.MutableSelectedState;
import org.jungrapht.visualization.transform.*;
import org.jungrapht.visualization.transform.shape.MagnifyImageLensSupport;
import org.jungrapht.visualization.transform.shape.MagnifyShapeTransformer;

import docking.ActionContext;
import docking.DockingActionProxy;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingAction;
import docking.action.builder.*;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.options.editor.OptionsDialog;
import docking.widgets.EventTrigger;
import docking.widgets.OptionDialog;
import generic.util.WindowUtilities;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.graph.AttributeFilters;
import ghidra.graph.job.GraphJobRunner;
import ghidra.graph.viewer.popup.*;
import ghidra.graph.visualization.mouse.*;
import ghidra.service.graph.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

/**
 * Delegates to a {@link VisualizationViewer} to draw a graph visualization
 * 
 * <P>This graph uses the following properties:
 * <UL>
 *  <LI>selectedVertexColor - hex color using '0x' or '#', with 6 digits
 *  </LI>
 *  <LI>selectedEdgeColor - hex color using '0x' or '#', with 6 digits
 *  </LI>
 *  <LI>displayVerticesAsIcons - if true, shapes will be used to draw vertices based upon 
 *      {@link GhidraIconCache}; false, then vertex shapes will be created from 
 *      {@link ProgramGraphFunctions#getVertexShape(Attributed)}
 *  </LI>
 *  <LI>vertexLabelPosition - see {@link Position}
 *  </LI>
 *  <LI>initialLayoutAlgorithm - the name of the layout algorithm to be used for the initial 
 *      graph layout
 *  </LI>
 * </UL>
 * 
 */
public class DefaultGraphDisplay implements GraphDisplay {

	private static final String ACTION_OWNER = "GraphServices";

	private static final Dimension PREFERRED_VIEW_SIZE = new Dimension(1000, 1000);
	private static final Dimension PREFERRED_LAYOUT_SIZE = new Dimension(3000, 3000);

	// layout algorithm categories
	static final String MIN_CROSS = "Hierarchical MinCross";
	static final String VERT_MIN_CROSS = "Vertical Hierarchical MinCross";

	private Set<DockingActionIf> addedActions = new LinkedHashSet<>();
	private GraphDisplayListener listener = new DummyGraphDisplayListener();
	private String title;

	private AttributedGraph graph;

	/**
	 * a unique id for this {@link GraphDisplay}
	 */
	private final int displayId;

	/**
	 * The delegate viewer to display the ProgramGraph
	 */
	private final VisualizationViewer<AttributedVertex, AttributedEdge> viewer;

	/**
	 * The {@link PluginTool}
	 */
	private final PluginTool tool;

	private final DefaultGraphDisplayComponentProvider componentProvider;

	/**
	 * Whether to ensure the focused vertex is visible, scrolling if necessary
	 * the visualization in order to center the selected vertex
	 * or the center of the set of selected vertices
	 */
	private boolean ensureVertexIsVisible = false;

	/**
	 * Allows selection of various {@link LayoutAlgorithm} ('arrangements')
	 */
	private final LayoutTransitionManager layoutTransitionManager;

	/**
	 * Provides graph displays for supplied graphs
	 */
	private final DefaultGraphDisplayProvider graphDisplayProvider;
	/**
	 * the vertex that has been nominated to be 'focused' in the graph display and listing
	 */
	private AttributedVertex focusedVertex;

	/**
	 * Runs animation jobs for updating the display
	 */
	private final GraphJobRunner jobRunner = new GraphJobRunner();

	/**
	 * a satellite view that shows in the lower left corner as a birds-eye view of the graph display
	 */
	private final SatelliteVisualizationViewer<AttributedVertex, AttributedEdge> satelliteViewer;

	private FilterDialog filterDialog;
	private AttributeFilters edgeFilters;
	private AttributeFilters vertexFilters;

	private GraphRenderer graphRenderer = new DefaultGraphRenderer();

	/**
	 * Multi-selection is done in a free-form traced shape instead of a rectangle
	 */
	private boolean freeFormSelection;

	/**
	 * Handles all mouse interaction
	 */
	private JgtGraphMouse graphMouse;

	private ToggleDockingAction hideSelectedAction;
	private ToggleDockingAction hideUnselectedAction;
	private SwitchableSelectionItemListener switchableSelectionListener;

	private ToggleDockingAction togglePopupsAction;
	private PopupRegulator<AttributedVertex, AttributedEdge> popupRegulator;
	private GhidraGraphCollapser graphCollapser;

	private MultiSelectedVertexPaintable<AttributedVertex, AttributedEdge> multiSelectedVertexPaintable;

	// manages highlight painting of a single selected vertex
	private SingleSelectedVertexPaintable<AttributedVertex, AttributedEdge> singleSelectedVertexPaintable;

	private SelectedEdgePaintable<AttributedVertex, AttributedEdge> selectedEdgePaintable;

	private GraphDisplayOptions graphDisplayOptions = GraphDisplayOptions.DEFAULT;

	private ChangeListener graphDisplayOptionsChangeListener;

	private MultiStateDockingAction<String> layoutAction;

	/**
	 * Create the initial display, the graph-less visualization viewer, and its controls
	 * @param displayProvider provides a {@link PluginTool} for Docking features
	 * @param id the unique display id
	 */
	DefaultGraphDisplay(DefaultGraphDisplayProvider displayProvider, int id) {
		this.graphDisplayProvider = displayProvider;
		this.displayId = id;
		this.tool = graphDisplayProvider.getPluginTool();
		this.viewer = createViewer();
		buildHighlighers();

		componentProvider = new DefaultGraphDisplayComponentProvider(this, tool);
		componentProvider.addToTool();
		satelliteViewer = createSatelliteViewer(viewer);
		if (graphDisplayProvider.getDefaultSatelliteState()) {
			viewer.getComponent().add(satelliteViewer.getComponent());
		}
		layoutTransitionManager =
			new LayoutTransitionManager(viewer, this::isRoot, graphRenderer);

		viewer.getComponent().addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				super.componentResized(e);
				Component vv = e.getComponent();
				Dimension vvd = vv.getSize();
				Dimension sd = satelliteViewer.getSize();
				java.awt.Point p = new java.awt.Point(vvd.width - sd.width, vvd.height - sd.height);
				satelliteViewer.getComponent().setBounds(p.x, p.y, sd.width, sd.height);
				satelliteViewer.scaleToLayout();
			}
		});

		viewer.setInitialDimensionFunction(InitialDimensionFunction
				.builder(viewer.getRenderContext().getVertexBoundsFunction())
				.build());
		createToolbarActions();
		createPopupActions();
		connectSelectionStateListeners();
		graphDisplayOptionsChangeListener = e -> refreshViewer();
	}

	private void refreshViewer() {
		graphRenderer.clearCache();

		graphRenderer.initializeViewer(viewer);

		// bug in jungraphT library where vertex selection color doesn't update, but edge selection
		// color does, so just rebuild the highlighter
		buildHighlighers();
		viewer.repaint();
	}

	private Color getSelectedVertexColor() {
		return graphRenderer.getVertexSelectionColor();
	}

	private Color getSelectedEdgeColor() {
		return graphRenderer.getEdgeSelectionColor();
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
			new LensMagnificationGraphMousePlugin(1.f, 60.f, .2f) {
				// Override to address a bug when using a high resolution mouse wheel.
				// May be removed when jungrapht-visualization version is updated
				@Override
				public void mouseWheelMoved(MouseWheelEvent e) {
					if (e.getWheelRotation() != 0) {
						super.mouseWheelMoved(e);
					}
				}
			};

		MutableTransformer transformer = viewer.getRenderContext()
				.getMultiLayerTransformer()
				.getTransformer(VIEW);

		MagnifyShapeTransformer shapeTransformer = MagnifyShapeTransformer.builder(lens)
				// this lens' delegate is the viewer's VIEW layer, abandoned above
				.delegate(transformer)
				.build();
		LensGraphMouse lensGraphMouse =
			DefaultLensGraphMouse.builder().magnificationPlugin(magnificationPlugin).build();
		return MagnifyImageLensSupport.builder(viewer)
				.lensTransformer(shapeTransformer)
				.lensGraphMouse(lensGraphMouse)
				.build();
	}

	/**
	 * create the highlighters ({@code Paintable}s to show which vertices have been selected or focused)
	 */
	private void buildHighlighers() {

		viewer.removePostRenderPaintable(multiSelectedVertexPaintable);

		viewer.removePostRenderPaintable(singleSelectedVertexPaintable);

		// for highlighting of multiple selected vertices
		this.multiSelectedVertexPaintable =
			MultiSelectedVertexPaintable.builder(viewer)
					.selectionStrokeMin(15.f)
					.selectionPaint(getSelectedVertexColor())
					.useBounds(true)
					.useOval(true)
					.highlightScale(1.15)
					.fillHighlight(false)
					.build();

		// manages highlight painting of a single selected vertex
		this.singleSelectedVertexPaintable =
			SingleSelectedVertexPaintable.builder(viewer)
					.selectionStrokeMin(4.f)
					.selectionPaint(getSelectedVertexColor())
					.selectedVertexFunction(vs -> this.focusedVertex)
					.build();

		// draws the selection highlights
		viewer.addPreRenderPaintable(multiSelectedVertexPaintable);

		// draws the location arrow
		viewer.addPostRenderPaintable(singleSelectedVertexPaintable);

		viewer.removePreRenderPaintable(selectedEdgePaintable);

		this.selectedEdgePaintable = SelectedEdgePaintable.builder(viewer)
				.selectionPaintFunction(e -> getSelectedEdgeColor())
				.selectionStrokeMultiplier(2)
				.build();

		viewer.addPreRenderPaintable(selectedEdgePaintable);

	}

	/**
	 * create the action icon buttons on the upper-right of the graph display window
	 */
	private void createToolbarActions() {

		// create a toggle for 'scroll to selected vertex'
		new ToggleActionBuilder("Scroll To Selection", ACTION_OWNER)
				.toolBarIcon(Icons.NAVIGATE_ON_INCOMING_EVENT_ICON)
				.description("Ensure that the 'focused' vertex is visible")
				.selected(true)
				.onAction(context -> ensureVertexIsVisible =
					((AbstractButton) context.getSourceObject()).isSelected())
				.buildAndInstallLocal(componentProvider);

		this.ensureVertexIsVisible = true;  // since we intialized action to selected

		// create a toggle for enabling 'free-form' selection: selection is
		// inside of a traced shape instead of a rectangle
		new ToggleActionBuilder("Free-Form Selection", ACTION_OWNER)
				.toolBarIcon(DefaultDisplayGraphIcons.LASSO_ICON)
				.description("Trace Free-Form Shape to select multiple vertices (CTRL-click-drag)")
				.selected(false)
				.onAction(context -> freeFormSelection =
					((AbstractButton) context.getSourceObject()).isSelected())
				.buildAndInstallLocal(componentProvider);

		// create an icon button to display the satellite view
		new ToggleActionBuilder("SatelliteView", ACTION_OWNER).description("Show Satellite View")
				.toolBarIcon(DefaultDisplayGraphIcons.SATELLITE_VIEW_ICON)
				.onAction(this::toggleSatellite)
				.selected(graphDisplayProvider.getDefaultSatelliteState())
				.buildAndInstallLocal(componentProvider);

		// create an icon button to reset the view transformations to identity (scaled to layout)
		new ActionBuilder("Reset View", ACTION_OWNER)
				.description("Fit Graph to Window")
				.toolBarIcon(DefaultDisplayGraphIcons.FIT_TO_WINDOW)
				.onAction(context -> centerAndScale())
				.buildAndInstallLocal(componentProvider);

		// create a button to show the view magnify lens
		LensSupport<LensGraphMouse> magnifyViewSupport = createMagnifier();
		ToggleDockingAction lensToggle = new ToggleActionBuilder("View Magnifier", ACTION_OWNER)
				.description("Show View Magnifier")
				.toolBarIcon(DefaultDisplayGraphIcons.VIEW_MAGNIFIER_ICON)
				.onAction(context -> magnifyViewSupport.activate(
					((AbstractButton) context.getSourceObject()).isSelected()))
				.build();
		magnifyViewSupport.addItemListener(
			itemEvent -> lensToggle.setSelected(itemEvent.getStateChange() == ItemEvent.SELECTED));
		componentProvider.addLocalAction(lensToggle);

		// create an action button to show a dialog with generated filters
		new ActionBuilder("Show Filters", ACTION_OWNER).description("Show Graph Filters")
				.toolBarIcon(DefaultDisplayGraphIcons.FILTER_ICON)
				.onAction(context -> showFilterDialog())
				.buildAndInstallLocal(componentProvider);

		// create a menu with graph layout algorithm selections
		List<ActionState<String>> layoutActionStates = getLayoutActionStates();
		layoutAction = new MultiStateActionBuilder<String>("Arrangement", ACTION_OWNER)
				.description("Arrangement: " + layoutActionStates.get(0).getName())
				.toolBarIcon(DefaultDisplayGraphIcons.LAYOUT_ALGORITHM_ICON)
				.useCheckboxForIcons(true)
				.onActionStateChanged((s, t) -> layoutChanged(s.getName()))
				.addStates(layoutActionStates)
				.buildAndInstallLocal(componentProvider);
	}

	private void createPopupActions() {
		new ActionBuilder("Select Vertex", ACTION_OWNER)
				.popupMenuPath("Select Vertex")
				.popupMenuGroup("selection", "1")
				.withContext(VertexGraphActionContext.class)
				.enabledWhen(c -> !isSelected(c.getClickedVertex()))
				.onAction(c -> viewer.getSelectedVertexState().select(c.getClickedVertex()))
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Deselect Vertex", ACTION_OWNER)
				.popupMenuPath("Deselect Vertex")
				.popupMenuGroup("selection", "2")
				.withContext(VertexGraphActionContext.class)
				.enabledWhen(c -> isSelected(c.getClickedVertex()))
				.onAction(c -> viewer.getSelectedVertexState().deselect(c.getClickedVertex()))
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Select Edge", ACTION_OWNER)
				.popupMenuPath("Select Edge")
				.popupMenuGroup("selection", "1")
				.withContext(EdgeGraphActionContext.class)
				.enabledWhen(c -> !isSelected(c.getClickedEdge()))
				.onAction(c -> selectEdge(c.getClickedEdge()))
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Deselect Edge", ACTION_OWNER)
				.popupMenuPath("Deselect Edge")
				.popupMenuGroup("selection", "2")
				.withContext(EdgeGraphActionContext.class)
				.enabledWhen(c -> isSelected(c.getClickedEdge()))
				.onAction(c -> deselectEdge(c.getClickedEdge()))
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Edge Source", ACTION_OWNER)
				.popupMenuPath("Go To Edge Source")
				.popupMenuGroup("Go To")
				.withContext(EdgeGraphActionContext.class)
				.onAction(c -> {
					selectEdge(c.getClickedEdge());
					setFocusedVertex(graph.getEdgeSource(c.getClickedEdge()));
				})
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Edge Target", ACTION_OWNER)
				.popupMenuPath("Go To Edge Target")
				.popupMenuGroup("Go To")
				.withContext(EdgeGraphActionContext.class)
				.onAction(c -> {
					selectEdge(c.getClickedEdge());
					setFocusedVertex(graph.getEdgeTarget(c.getClickedEdge()));
				})
				.buildAndInstallLocal(componentProvider);

		hideSelectedAction = new ToggleActionBuilder("Hide Selected", ACTION_OWNER)
				.popupMenuPath("Hide Selected")
				.popupMenuGroup("z", "1")
				.description("Toggles whether or not to show selected vertices and edges")
				.onAction(c -> manageVertexDisplay())
				.buildAndInstallLocal(componentProvider);

		hideUnselectedAction = new ToggleActionBuilder("Hide Unselected", ACTION_OWNER)
				.popupMenuPath("Hide Unselected")
				.popupMenuGroup("z", "2")
				.description("Toggles whether or not to show selected vertices and edges")
				.onAction(c -> manageVertexDisplay())
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Invert Selection", ACTION_OWNER)
				.popupMenuPath("Invert Selection")
				.popupMenuGroup("z", "3")
				.description("Inverts the current selection")
				.onAction(c -> invertSelection())
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Grow Selection To Targets", ACTION_OWNER)
				.popupMenuPath("Grow Selection To Targets")
				.popupMenuGroup("z", "4")
				.description("Extends the current selection by including the target vertex " +
					"of all edges whose source is selected")
				.keyBinding("ctrl O")
				.enabledWhen(c -> !isAllSelected(getTargetVerticesFromSelected()))
				.onAction(c -> growSelection(getTargetVerticesFromSelected()))
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Grow Selection From Sources", ACTION_OWNER)
				.popupMenuPath("Grow Selection From Sources")
				.popupMenuGroup("z", "4")
				.description("Extends the current selection by including the target vertex " +
					"of all edges whose source is selected")
				.keyBinding("ctrl I")
				.enabledWhen(c -> !isAllSelected(getSourceVerticesFromSelected()))
				.onAction(c -> growSelection(getSourceVerticesFromSelected()))
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Grow Selection To Entire Component", ACTION_OWNER)
				.popupMenuPath("Grow Selection To Entire Component")
				.popupMenuGroup("z", "4")
				.description(
					"Extends the current selection by including the target/source vertices " +
						"of all edges whose source/target is selected")
				.keyBinding("ctrl C")
				.enabledWhen(c -> !isAllSelected(getSourceVerticesFromSelected()) ||
					!isAllSelected(getTargetVerticesFromSelected()))
				.onAction(c -> growSelection(getAllComponentVerticesFromSelected()))
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Clear Selection", ACTION_OWNER)
				.popupMenuPath("Clear Selection")
				.popupMenuGroup("z", "5")
				.keyBinding("escape")
				.enabledWhen(c -> hasSelection())
				.onAction(c -> clearSelection(true))
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Create Subgraph", ACTION_OWNER)
				.popupMenuPath("Display Selected as New Graph")
				.popupMenuGroup("zz", "5")
				.description("Creates a subgraph from the selected nodes")
				.enabledWhen(c -> !viewer.getSelectedVertices().isEmpty())
				.onAction(c -> createAndDisplaySubGraph())
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Collapse Selected", ACTION_OWNER)
				.popupMenuPath("Collapse Selected Vertices")
				.popupMenuGroup("zz", "6")
				.description("Collapses the selected vertices into one collapsed vertex")
				.onAction(c -> groupSelectedVertices())
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Expand Selected", ACTION_OWNER)
				.popupMenuPath("Expand Selected Vertices")
				.popupMenuGroup("zz", "6")
				.description("Expands all selected collapsed vertices into their previous form")
				.onAction(c -> ungroupSelectedVertices())
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Graph Type Display Options", ACTION_OWNER)
				.popupMenuPath("Graph Type Options ...")
				.popupMenuGroup("zzz")
				.menuPath("Graph Type Options ...")
				.description("Brings up option editor for configuring vertex and edge types.")
				.onAction(c -> editGraphDisplayOptions())
				.buildAndInstallLocal(componentProvider);

		togglePopupsAction = new ToggleActionBuilder("Display Popup Windows", ACTION_OWNER)
				.popupMenuPath("Display Popup Windows")
				.popupMenuGroup("zz", "1")
				.description("Toggles whether or not to show popup windows, such as tool tips")
				.selected(true)
				.onAction(c -> popupRegulator.setPopupsVisible(togglePopupsAction.isSelected()))
				.buildAndInstallLocal(componentProvider);
		popupRegulator.setPopupsVisible(togglePopupsAction.isSelected());

	}

	private void editGraphDisplayOptions() {
		String rootOptionsName = graphDisplayOptions.getRootOptionsName();
		String relativePath = rootOptionsName + ".Vertex Colors";

		// if the options are registered in the tool options, just show them
		// otherwise, create a transient options and create an options dialog. This will
		// allow the user to edit the options for the current graph instance.

		if (graphDisplayOptions.isRegisteredWithTool()) {
			OptionsService service = tool.getService(OptionsService.class);
			service.showOptionsDialog("Graph." + relativePath, "");
		}
		else {
			ToolOptions transientOptions = new ToolOptions("Graph");
			HelpLocation help = new HelpLocation("GraphServices", "Graph Type Display Options");
			graphDisplayOptions.registerOptions(transientOptions, help);
			transientOptions.addOptionsChangeListener(graphDisplayOptions);
			Options[] optionsArray = new Options[] { transientOptions };
			String dialogTitle = "Graph Instance Settings (Not Saved in Tool Options)";
			OptionsDialog dialog = new OptionsDialog(dialogTitle, "Graph", optionsArray, null);
			// we have one less level for these transient tool options, so no need to prepend "graph."
			dialog.displayCategory(relativePath, "");
			tool.showDialog(dialog, componentProvider);
		}
	}

	/**
	 * Group the selected vertices into one vertex that represents them all
	 */
	private void groupSelectedVertices() {
		AttributedVertex vertex = graphCollapser.groupSelectedVertices();
		if (vertex != null) {
			askToNameGroupVertex(vertex);
			focusedVertex = vertex;
			scrollToSelected(vertex);
		}
	}

	private void askToNameGroupVertex(AttributedVertex vertex) {
		String name = vertex.getName();
		String userName = OptionDialog.showInputMultilineDialog(null, "Enter Group Vertex Text",
			"Text", name);

		updateVertexName(vertex, userName != null ? userName : name);
	}

	/**
	 * Ungroup the selected vertices. If the focusedVertex is no longer
	 * in the graph, null it. This will happen if the focusedVertex was
	 * the GroupVertex
	 */
	private void ungroupSelectedVertices() {
		graphCollapser.ungroupSelectedVertices();
		if (!graph.containsVertex(focusedVertex)) {
			focusedVertex = null;
		}
	}

	private void clearSelection(boolean fireEvents) {
		viewer.getSelectedVertexState().clear(fireEvents);
		viewer.getSelectedEdgeState().clear(fireEvents);
	}

	private boolean hasSelection() {
		return !(viewer.getSelectedVertices().isEmpty() &&
			viewer.getSelectedEdges().isEmpty());
	}

	private boolean isSelected(AttributedVertex v) {
		return viewer.getSelectedVertices().contains(v);
	}

	private boolean isSelected(AttributedEdge e) {
		return viewer.getSelectedEdges().contains(e);
	}

	private void createAndDisplaySubGraph() {
		GraphDisplay display = graphDisplayProvider.getGraphDisplay(false, TaskMonitor.DUMMY);
		try {
			display.setGraph(createSubGraph(), graphRenderer.getGraphDisplayOptions(),
				title + " - Sub-graph", false, TaskMonitor.DUMMY);
			display.setGraphDisplayListener(listener.cloneWith(display));
			copyActionsToNewGraph((DefaultGraphDisplay) display);
		}
		catch (CancelledException e) {
			// using Dummy, so can't happen
		}
	}

	private AttributedGraph createSubGraph() {
		Set<AttributedVertex> selected = viewer.getSelectedVertices();
		Graph<AttributedVertex, AttributedEdge> subGraph = new AsSubgraph<>(graph, selected);

		AttributedGraph newGraph =
			new AttributedGraph(graph.getName() + ": subgraph", graph.getGraphType());
		subGraph.vertexSet().forEach(newGraph::addVertex);
		for (AttributedEdge e : subGraph.edgeSet()) {
			AttributedVertex source = subGraph.getEdgeSource(e);
			AttributedVertex target = subGraph.getEdgeTarget(e);
			newGraph.addEdge(source, target, e);
		}
		return newGraph;
	}

	private void growSelection(Set<AttributedVertex> vertices) {
		viewer.getSelectedVertexState().select(vertices);
	}

	// select all the edges that connect the supplied vertices
	private void selectEdgesConnecting(Collection<AttributedVertex> vertices) {
		viewer.getSelectedEdgeState()
				.select(
					graph.edgeSet()
							.stream()
							.filter(
								e -> {
									AttributedVertex source = graph.getEdgeSource(e);
									AttributedVertex target = graph.getEdgeTarget(e);
									return vertices.contains(source) && vertices.contains(target);
								})
							.collect(Collectors.toSet()));

	}

	private boolean isAllSelected(Set<AttributedVertex> vertices) {
		return viewer.getSelectedVertices().containsAll(vertices);
	}

	private Set<AttributedVertex> getSourceVerticesFromSelected() {
		Set<AttributedVertex> selectedVertices = getSelectedVertices();
		Set<AttributedVertex> sources = new HashSet<>(selectedVertices);
		for (AttributedVertex v : selectedVertices) {
			Set<AttributedEdge> edges = graph.incomingEdgesOf(v);
			edges.forEach(e -> sources.add(graph.getEdgeSource(e)));
		}
		return sources;
	}

	private Set<AttributedVertex> getUnselectedSourceVerticesFromSelected() {
		MutableSelectedState<AttributedVertex> selectedVertexState =
			viewer.getSelectedVertexState();
		return getSourceVerticesFromSelected().stream()
				.filter(v -> !selectedVertexState.isSelected(v))
				.collect(Collectors.toSet());
	}

	private Set<AttributedVertex> getTargetVerticesFromSelected() {
		Set<AttributedVertex> selectedVertices = getSelectedVertices();
		Set<AttributedVertex> targets = new HashSet<>(selectedVertices);
		for (AttributedVertex v : selectedVertices) {
			Set<AttributedEdge> edges = graph.outgoingEdgesOf(v);
			edges.forEach(e -> targets.add(graph.getEdgeTarget(e)));
		}
		return targets;
	}

	private Set<AttributedVertex> getUnselectedTargetVerticesFromSelected() {
		MutableSelectedState<AttributedVertex> selectedVertexState =
			viewer.getSelectedVertexState();
		return getTargetVerticesFromSelected().stream()
				.filter(v -> !selectedVertexState.isSelected(v))
				.collect(Collectors.toSet());
	}

	private Set<AttributedVertex> getAllDownstreamVerticesFromSelected() {
		Set<AttributedVertex> downstream = new HashSet<>();
		Set<AttributedVertex> targets = getUnselectedTargetVerticesFromSelected();
		while (!targets.isEmpty()) {
			downstream.addAll(targets);
			growSelection(targets);
			targets = getUnselectedTargetVerticesFromSelected();
		}
		return downstream;
	}

	private Set<AttributedVertex> getAllUpstreamVerticesFromSelected() {
		Set<AttributedVertex> upstream = new HashSet<>();
		Set<AttributedVertex> sources = getUnselectedSourceVerticesFromSelected();
		while (!sources.isEmpty()) {
			growSelection(sources);
			upstream.addAll(sources);
			sources = getUnselectedSourceVerticesFromSelected();
		}
		return upstream;
	}

	/**
	 * Gather all source and target vertices until there are no more available.
	 * @return all the vertices in the component(s) of the selected vertices
	 */
	public Set<AttributedVertex> getAllComponentVerticesFromSelected() {
		Set<AttributedVertex> componentVertices = new HashSet<>(viewer.getSelectedVertices());
		Set<AttributedVertex> downstream = getAllDownstreamVerticesFromSelected();
		Set<AttributedVertex> upstream = getAllUpstreamVerticesFromSelected();
		while (!downstream.isEmpty() || !upstream.isEmpty()) {
			componentVertices.addAll(downstream);
			componentVertices.addAll(upstream);
			downstream = getAllDownstreamVerticesFromSelected();
			upstream = getAllUpstreamVerticesFromSelected();
		}
		return componentVertices;
	}

	private void invertSelection() {
		switchableSelectionListener.setEnabled(false);
		try {
			MutableSelectedState<AttributedVertex> selectedVertexState =
				viewer.getSelectedVertexState();
			for (AttributedVertex v : graph.vertexSet()) {
				if (selectedVertexState.isSelected(v)) {
					selectedVertexState.deselect(v);
				}
				else {
					selectedVertexState.select(v);
				}
			}
			Set<AttributedVertex> selected = selectedVertexState.getSelected();
			notifySelectionChanged(selected);
		}
		finally {
			switchableSelectionListener.setEnabled(true);
		}
	}

	private List<ActionState<String>> getLayoutActionStates() {
		List<String> names = LayoutAlgorithmNames.getLayoutAlgorithmNames();
		List<ActionState<String>> actionStates = new ArrayList<>();
		for (String layoutName : names) {
			ActionState<String> state = new ActionState<>(layoutName,
				DefaultDisplayGraphIcons.LAYOUT_ALGORITHM_ICON, layoutName);

			// condense hierarchical action help to the top-level help description
			String anchor = layoutName;
			if (layoutName.contains(VERT_MIN_CROSS)) {
				anchor = VERT_MIN_CROSS;
			}
			else if (layoutName.contains(MIN_CROSS)) {
				anchor = MIN_CROSS;
			}

			state.setHelpLocation(new HelpLocation(ACTION_OWNER, anchor));
			actionStates.add(state);
		}
		return actionStates;
	}

	private void layoutChanged(String layoutName) {
		TaskLauncher.launch(new SetLayoutTask(viewer, layoutTransitionManager, layoutName));
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
		boolean selected = ((AbstractButton) context.getSourceObject()).isSelected();
		graphDisplayProvider.setDefaultSatelliteState(selected);
		if (selected) {
			viewer.getComponent().add(satelliteViewer.getComponent());
			satelliteViewer.scaleToLayout();
		}
		else {
			viewer.getComponent().remove(satelliteViewer.getComponent());
		}
		viewer.repaint();
	}

	private SatelliteVisualizationViewer<AttributedVertex, AttributedEdge> createSatelliteViewer(
			VisualizationViewer<AttributedVertex, AttributedEdge> parentViewer) {
		Dimension viewerSize = parentViewer.getSize();
		Dimension satelliteSize = new Dimension(
			viewerSize.width / 4, viewerSize.height / 4);
		final SatelliteVisualizationViewer<AttributedVertex, AttributedEdge> satellite =
			SatelliteVisualizationViewer.builder(parentViewer)
					.viewSize(satelliteSize)
					.build();

		//
		// JUNGRAPHT CHANGE 3
		//
		satellite.setGraphMouse(new JgtSatelliteGraphMouse());

		RenderContext<AttributedVertex, AttributedEdge> renderer = satellite.getRenderContext();
		RenderContext<AttributedVertex, AttributedEdge> viewerRenderer = viewer.getRenderContext();
		renderer.setEdgeDrawPaintFunction(viewerRenderer.getEdgeDrawPaintFunction());
		renderer.setEdgeStrokeFunction(viewerRenderer.getEdgeArrowStrokeFunction());
		renderer.setEdgeDrawPaintFunction(viewerRenderer.getEdgeDrawPaintFunction());
		renderer.setVertexFillPaintFunction(viewerRenderer.getVertexFillPaintFunction());
		renderer.setVertexDrawPaintFunction(viewerRenderer.getVertexDrawPaintFunction());

		satellite.scaleToLayout();
		renderer.setVertexLabelFunction(n -> null);

		// the satellite should use the same vertex predicate so that it has the same vertices
		// as the main graph
		renderer.setVertexIncludePredicate(v -> viewerRenderer.getVertexIncludePredicate().test(v));
		renderer.setEdgeIncludePredicate(e -> viewerRenderer.getEdgeIncludePredicate().test(e));
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

	@Override
	public void close() {
		graphDisplayProvider.remove(this);
		if (listener != null) {
			listener.graphClosed();
		}
		listener = null;
		componentProvider.closeComponent();
		if (graphDisplayOptions != null) {
			graphDisplayOptions.removeChangeListener(graphDisplayOptionsChangeListener);
		}
	}

	@Override
	public void setGraphDisplayListener(GraphDisplayListener listener) {
		if (this.listener != null) {
			this.listener.graphClosed();
		}
		this.listener = listener;
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

	public void setFocusedVertex(AttributedVertex vertex) {
		setFocusedVertex(vertex, EventTrigger.API_CALL);
	}

	@Override
	public void setFocusedVertex(AttributedVertex vertex, EventTrigger eventTrigger) {
		boolean changed = this.focusedVertex != vertex;
		this.focusedVertex = graphCollapser.getOutermostVertex(vertex);
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
	 * fire an event to notify the selected vertices changed
	 * @param selected the list of selected vertices
	 */
	private void notifySelectionChanged(Set<AttributedVertex> selected) {
		// replace any group vertices with their individual vertices.
		Set<AttributedVertex> flattened = GroupVertex.flatten(selected);
		Swing.runLater(() -> listener.selectionChanged(flattened));
	}

	public static Set<AttributedVertex> flatten(Collection<AttributedVertex> vertices) {
		Set<AttributedVertex> set = new HashSet<>();
		for (AttributedVertex vertex : vertices) {
			if (vertex instanceof GroupVertex) {
				set.addAll(((GroupVertex) vertex).getContainedVertices());
			}
			else {
				set.add(vertex);
			}
		}
		return set;
	}

	/**
	 * fire and event to say the focused vertex changed
	 * @param vertex the new focused vertex
	 */
	private void notifyLocationFocusChanged(AttributedVertex vertex) {
		AttributedVertex focus =
			vertex instanceof GroupVertex ? ((GroupVertex) vertex).getFirst() : vertex;
		Swing.runLater(() -> listener.locationFocusChanged(focus));
	}

	@Override
	public void selectVertices(Set<AttributedVertex> selected, EventTrigger eventTrigger) {
		// if we are not to fire events, turn off the selection listener we provided to the
		// graphing library.
		boolean fireEvents = eventTrigger != EventTrigger.INTERNAL_ONLY;
		switchableSelectionListener.setEnabled(fireEvents);

		try {
			Set<AttributedVertex> vertices = graphCollapser.convertToOutermostVertices(selected);
			MutableSelectedState<AttributedVertex> nodeSelectedState =
				viewer.getSelectedVertexState();
			nodeSelectedState.clear();
			if (!vertices.isEmpty()) {
				nodeSelectedState.select(vertices, fireEvents);
				if (!fireEvents) {
					// need to make explicit call since event not fired
					selectEdgesConnecting(vertices);
				}
				scrollToSelected(vertices);
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
		clearSelection(false);
		focusedVertex = null;
		graph = attributedGraph;

		configureViewerPreferredSize();

		Swing.runNow(() -> {
			// set the graph but defer the layout algorithm setting
			viewer.getVisualizationModel().setGraph(graph, false);
			configureFilters();
			setInitialLayoutAlgorithm();
		});
		componentProvider.setVisible(true);
	}

	private void setInitialLayoutAlgorithm() {
		String layoutAlgorithmName = graphDisplayOptions.getDefaultLayoutAlgorithmNameLayout();
		layoutAction.setCurrentActionStateByUserData(layoutAlgorithmName);
		TaskLauncher
				.launch(new SetLayoutTask(viewer, layoutTransitionManager, layoutAlgorithmName));
	}

	/**
	 * Determines if a vertex is a root.  For our purpose, a root either has no incoming edges
	 * or if all edges of a vertex are 'loop' edges
	 * @param vertex the vertex to test if it is a root
	 * @return true if the vertex is a root
	 */
	private boolean isRoot(AttributedVertex vertex) {
		Set<AttributedEdge> incomingEdgesOf = graph.incomingEdgesOf(vertex);
		return incomingEdgesOf.isEmpty() ||
			graph.incomingEdgesOf(vertex).equals(graph.outgoingEdgesOf(vertex));
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
				.paintFunction(v -> graphDisplayOptions.getVertexColor(v))
				.build();

		vertexFilters.addItemListener(item -> {
			@SuppressWarnings("unchecked")
			Set<String> selected = (Set<String>) item.getItem();
			viewer.getRenderContext()
					.setVertexIncludePredicate(
						v -> v.getAttributes().values().stream().noneMatch(selected::contains));
			viewer.repaint();

		});

		edgeFilters = AttributeFilters.builder()
				.exclude(Set.of("*ToKey", "*FromKey", "Address", "Name"))
				.elements(edges)
				.maxFactor(.01)
				.buttonSupplier(JRadioButton::new)
				.paintFunction(e -> graphDisplayOptions.getEdgeColor(e))
				.build();

		edgeFilters.addItemListener(item -> {
			@SuppressWarnings("unchecked")
			Set<String> selected = (Set<String>) item.getItem();
			viewer.getRenderContext()
					.setEdgeIncludePredicate(
						e -> e.getAttributes().values().stream().noneMatch(selected::contains));
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

	private void setGraphDisplayOptions(GraphDisplayOptions options) {
		if (graphDisplayOptions != null) {
			graphDisplayOptions.removeChangeListener(graphDisplayOptionsChangeListener);
		}
		graphDisplayOptions = options;
		graphDisplayOptions.addChangeListener(graphDisplayOptionsChangeListener);
		graphRenderer.setGraphTypeDisplayOptions(options);
		refreshViewer();

	}

	@Override
	public void setGraph(AttributedGraph graph, GraphDisplayOptions options, String title,
			boolean append, TaskMonitor monitor) {
		setGraphDisplayOptions(options);
		if (append && Objects.equals(title, this.title) && this.graph != null) {
			graph = mergeGraphs(graph, this.graph);
		}

		this.title = title;
		componentProvider.setTitle(title);
		int count = graph.getVertexCount();
		if (count > options.getMaxNodeCount()) {
			Msg.showWarn(this, null, "Graph Not Rendered - Too many nodes!",
				"Exceeded limit of " + options.getMaxNodeCount() + " nodes.\n\n  Graph contained " +
					count +
					" nodes!");
			graph = new AttributedGraph("Aborted", graph.getGraphType(), "Too Many Nodes");
			graph.addVertex("1", "Graph Aborted");
		}
		doSetGraphData(graph);
		graphCollapser = new GhidraGraphCollapser(viewer);
		buildHighlighers();
	}

	private AttributedGraph mergeGraphs(AttributedGraph newGraph, AttributedGraph oldGraph) {
		for (AttributedVertex vertex : oldGraph.vertexSet()) {
			newGraph.addVertex(vertex);
		}
		for (AttributedEdge edge : oldGraph.edgeSet()) {
			AttributedVertex from = oldGraph.getEdgeSource(edge);
			AttributedVertex to = oldGraph.getEdgeTarget(edge);
			AttributedEdge newEdge = newGraph.addEdge(from, to);
			Map<String, String> attributeMap = edge.getAttributes();
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
		satelliteViewer.scaleToLayout();
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

		// they did not pick a vertex to center, so just center the graph
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
		graphRenderer.vertexChanged(vertex);
		viewer.repaint();
	}

	@Override
	public String getGraphTitle() {
		return title;
	}

	/**
	 * Create and return a {@link VisualizationViewer} to display graphs
	 * @return the new VisualizationViewer
	 */
	protected VisualizationViewer<AttributedVertex, AttributedEdge> createViewer() {
		VisualizationViewer<AttributedVertex, AttributedEdge> vv =
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
					centerAndScale();
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

		// We control tooltips with the PopupRegulator.  Use null values to disable the default 
		// tool tip mechanism
		vv.setVertexToolTipFunction(v -> null);
		vv.setEdgeToolTipFunction(e -> null);
		vv.setToolTipText(null);

		PopupSource<AttributedVertex, AttributedEdge> popupSource = new GraphDisplayPopupSource(vv);
		popupRegulator = new PopupRegulator<>(popupSource);

		RenderContext<AttributedVertex, AttributedEdge> renderContext = vv.getRenderContext();

		renderContext.getSelectedVertexState().addItemListener(item -> {
			renderContext.getSelectedEdgeState().clear();
			selectEdgesConnecting(renderContext.getSelectedVertexState().getSelected());
		});

		graphRenderer.initializeViewer(vv);

		vv.getComponent().requestFocus();
		vv.setBackground(Color.WHITE);
		MouseListener[] mouseListeners = vv.getComponent().getMouseListeners();
		for (MouseListener mouseListener : mouseListeners) {
			vv.getComponent().removeMouseListener(mouseListener);
		}

		graphMouse = new JgtGraphMouse(this, false);
		vv.setGraphMouse(graphMouse);

		return vv;
	}

	private void copyActionsToNewGraph(DefaultGraphDisplay display) {

		for (DockingActionIf action : addedActions) {
			if (display.containsAction(action)) {
				// ignore actions added by the graph itself and any actions that the end user may
				// accidentally add more than once
				continue;
			}

			display.addAction(new DockingActionProxy(action));
		}

	}

	private boolean containsAction(DockingActionIf action) {

		String name = action.getFullName(); // name and owner
		for (DockingActionIf existingAction : addedActions) {
			if (name.equals(existingAction.getFullName())) {
				return true;
			}
		}
		return false;
	}

	@Override
	public void addAction(DockingActionIf action) {

		if (containsAction(action)) {
			Msg.warn(this, "Action with same name and owner already exixts in graph: " +
				action.getFullName());
			return;
		}

		addedActions.add(action);
		Swing.runLater(() -> componentProvider.addLocalAction(action));
	}

	@Override
	public AttributedVertex getFocusedVertex() {
		return focusedVertex;
	}

	@Override
	public Set<AttributedVertex> getSelectedVertices() {
		return viewer.getSelectedVertices();
	}

	ActionContext getActionContext(MouseEvent e) {

		AttributedVertex pickedVertex = JgtUtils.getVertex(e, viewer);
		if (pickedVertex != null) {
			return new VertexGraphActionContext(componentProvider, graph, getSelectedVertices(),
				focusedVertex, pickedVertex);
		}

		AttributedEdge pickedEdge = JgtUtils.getEdge(e, viewer);
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

	/**
	 * Removes all externally added actions. This is called before re-using the graph window for a
	 * new graph which may add its own set of actions for that particular graph.
	 */
	void restoreToDefaultSetOfActions() {
		Swing.runLater(() -> {
			// remove all actions
			componentProvider.removeAllLocalActions();
			addedActions.clear();
			// put the standard graph actions back
			createToolbarActions();
			createPopupActions();
		});
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	// class passed to the PopupRegulator to help construct info popups for the graph
	private class GraphDisplayPopupSource implements PopupSource<AttributedVertex, AttributedEdge> {

		private VisualizationViewer<AttributedVertex, AttributedEdge> vv;

		public GraphDisplayPopupSource(VisualizationViewer<AttributedVertex, AttributedEdge> vv) {
			this.vv = vv;
		}

		@Override
		public ToolTipInfo<?> getToolTipInfo(MouseEvent event) {

			// check for a vertex hit first, otherwise, we get edge hits when we are hovering 
			// over a vertex, due to how edges are interpreted as existing all the way to the 
			// center point of a vertex
			AttributedVertex vertex = getVertex(event);
			if (vertex != null) {
				return new AttributedToolTipInfo(vertex, event);
			}

			AttributedEdge edge = getEdge(event);
			if (edge != null) {
				return new AttributedToolTipInfo(edge, event);
			}

			// no vertex or edge hit; just create a basic info that is essentially a null-object
			// placeholder to prevent NPEs
			return new AttributedToolTipInfo(vertex, event);
		}

		@Override
		public AttributedVertex getVertex(MouseEvent event) {

			LayoutModel<AttributedVertex> layoutModel =
				vv.getVisualizationModel().getLayoutModel();
			Point2D p = vv.getTransformSupport().inverseTransform(vv, event.getPoint());
			AttributedVertex vertex =
				vv.getPickSupport().getVertex(layoutModel, p.getX(), p.getY());
			return vertex;
		}

		@Override
		public AttributedEdge getEdge(MouseEvent event) {
			LayoutModel<AttributedVertex> layoutModel =
				vv.getVisualizationModel().getLayoutModel();
			Point2D p = vv.getTransformSupport().inverseTransform(vv, event.getPoint());
			AttributedEdge edge = vv.getPickSupport().getEdge(layoutModel, p.getX(), p.getY());
			return edge;
		}

		@Override
		public void addMouseMotionListener(MouseMotionListener l) {
			vv.getComponent().addMouseMotionListener(l);
		}

		@Override
		public void repaint() {
			vv.repaint();
		}

		@Override
		public Window getPopupParent() {
			return WindowUtilities.windowForComponent(vv.getComponent());
		}
	}

	/**
	 * Item listener for selection changes in the graph with the additional 
	 * capability of being able to disable the listener without removing it. 
	 */
	private class SwitchableSelectionItemListener implements ItemListener {
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
				Set<AttributedVertex> selectedVertices = getSelectedVertices();
				notifySelectionChanged(new HashSet<>(selectedVertices));

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
				Set<AttributedVertex> selectedVertices = getSelectedVertices();
				notifySelectionChanged(selectedVertices);
			}
			viewer.repaint();
		}

		void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}
	}

}
