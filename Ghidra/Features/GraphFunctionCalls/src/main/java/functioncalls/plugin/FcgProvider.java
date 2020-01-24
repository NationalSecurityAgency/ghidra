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
package functioncalls.plugin;

import static functioncalls.graph.FcgDirection.IN;
import static functioncalls.graph.FcgDirection.OUT;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import javax.swing.*;

import org.apache.commons.collections4.IterableUtils;

import com.google.common.cache.RemovalNotification;

import docking.*;
import docking.action.*;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import docking.widgets.OptionDialog;
import functioncalls.graph.*;
import functioncalls.graph.job.*;
import functioncalls.graph.layout.BowTieLayoutProvider;
import functioncalls.graph.renderer.FcgTooltipProvider;
import functioncalls.graph.view.FcgComponent;
import functioncalls.graph.view.FcgView;
import ghidra.app.context.NavigationActionContext;
import ghidra.graph.VisualGraphComponentProvider;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.actions.VgVertexContext;
import ghidra.graph.viewer.event.mouse.VertexMouseInfo;
import ghidra.graph.viewer.layout.*;
import ghidra.graph.viewer.vertex.VertexClickListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.Icons;
import util.CollectionUtils;

/**
 * The primary component provider for the {@link FunctionCallGraphPlugin}	
 */
public class FcgProvider
		extends VisualGraphComponentProvider<FcgVertex, FcgEdge, FunctionCallGraph> {

	/** A limit past which we will not attempt to display references for a given node */
	public static final int MAX_REFERENCES = 100;

	private static final String TOOLBAR_GROUP_A = "A";
	private static final String TOOLBAR_GROUP_B = "B";

	// here we sort popup groups by trial-and-error
	private static final String MENU_GROUP_EXPAND = "A";
	private static final String MENU_GROUP_GRAPH = "B";

	private static final String NAME = "Function Call Graph";

	private JComponent component;
	private FunctionCallGraphPlugin plugin;

	private FcgView view;
	private LayoutProvider<FcgVertex, FcgEdge, FunctionCallGraph> defaultLayoutProvider =
		new BowTieLayoutProvider();
	private LayoutProvider<FcgVertex, FcgEdge, FunctionCallGraph> layoutProvider;
	private Set<LayoutProvider<FcgVertex, FcgEdge, FunctionCallGraph>> layouts = new HashSet<>();

	private FcgDataFactory dataFactory;
	private FcgData graphData;

	private FcgVertexExpansionListener expansionListener = new ExpansionListener();

	private Predicate<FcgEdge> unfiltered = v -> true;
	private Predicate<FcgEdge> edgeNotInGraphFilter = e -> !graphData.getGraph().containsEdge(e);
	private Predicate<FcgVertex> vertexInGraphFilter = v -> graphData.getGraph().containsVertex(v);

	private ToggleDockingAction navigateIncomingToggleAction;

	public FcgProvider(Tool tool, FunctionCallGraphPlugin plugin) {
		super(tool, NAME, plugin.getName());
		this.plugin = plugin;

		dataFactory = new FcgDataFactory(this::graphDataCacheRemoved);
		graphData = dataFactory.create(null);

		buildComponent();

		// TODO upcoming multi-threading
		// runManager = new RunManager(GraphViewerUtils.GRAPH_BUILDER_THREAD_POOL_NAME, null);

		setWindowMenuGroup(FunctionCallGraphPlugin.NAME);
		setWindowGroup(FunctionCallGraphPlugin.NAME);
		setDefaultWindowPosition(WindowPosition.WINDOW);

		setHelpLocation(FunctionCallGraphPlugin.DEFAULT_HELP);
		// setIcon(FunctionCallGraphPlugin.ICON);

		addToTool();
		addSatelliteFeature(); // must be after addToTool();

		createLayouts();
		createActions();
	}

	@Override
	public FcgView getView() {
		return view;
	}

	@Override
	public void componentShown() {
		installGraph();
	}

	void locationChanged(ProgramLocation loc) {
		if (!navigateIncomingToggleAction.isSelected()) {
			return;
		}

		if (loc == null) {
			setFunction(null);
			return;
		}

		Program p = loc.getProgram();
		FunctionManager fm = p.getFunctionManager();
		Function f = fm.getFunctionContaining(loc.getAddress());
		setFunction(f);
	}

	void setFunction(Function f) {

		if (graphData.isFunction(f)) {
			return;
		}

		saveCurrentGraphPerspective();
		createAndInstallGraph(f);
		updateTitle();
	}

	private void saveCurrentGraphPerspective() {

		if (!isVisible()) {
			return;
		}

		if (!graphData.hasResults()) {
			return;
		}

		GraphPerspectiveInfo<FcgVertex, FcgEdge> info = view.generateGraphPerspective();
		graphData.setGraphPerspective(info);
	}

	private void updateTitle() {
		setTitle(NAME);
		String subTitle = null;
		if (graphData.hasResults()) {
			FunctionCallGraph graph = graphData.getGraph();
			subTitle = graphData.getFunction().getName() + " (" + graph.getVertexCount() +
				" functions; " + graph.getEdgeCount() + " edges)";
		}
		setSubTitle(subTitle);
	}

	private void rebuildCurrentGraph() {
		if (!graphData.hasResults()) {
			return;
		}

		Function function = graphData.getFunction();
		dataFactory.remove(function);
		createAndInstallGraph(function);
	}

	private void createAndInstallGraph(Function function) {

		graphData = dataFactory.create(function);
		if (!isVisible()) {
			return;
		}

		installGraph();
	}

	private void installGraph() {

		if (!graphData.hasResults()) {
			Address address = plugin.getCurrentAddress();
			if (address == null) {
				view.showErrorView("No function selected ");
			}
			else {
				view.showErrorView("No function containing " + address);
			}
			return;
		}

		if (graphData.isInitialized()) {

			view.setGraph(graphData.getGraph());
			view.setGraphPerspective(graphData.getGraphPerspective());
			return; // this is cached graph data for the current function
		}

		FunctionCallGraph graph = graphData.getGraph();
		setLayout(graph);

		FcgLevel source = FcgLevel.sourceLevel();
		FcgVertex sourceVertex = new FcgVertex(graphData.getFunction(), source, expansionListener);
		graph.setSource(sourceVertex);
		trackFunctionEdges(sourceVertex);

		view.setGraph(graph);
		FcgComponent gc = view.getGraphComponent();
		gc.setVertexFocused(sourceVertex);

		if (sourceVertex.canExpandIncomingReferences()) {
			expand(sourceVertex, IN);
		}

		if (sourceVertex.canExpandOutgoingReferences()) {
			expand(sourceVertex, OUT);
		}
	}

	private FcgVertex getOrCreateVertex(Function f, FcgLevel level) {
		FunctionCallGraph graph = graphData.getGraph();
		FcgVertex v = graph.getVertex(f);
		if (v != null) {
			return v;
		}

		v = new FcgVertex(f, level, expansionListener);
		trackFunctionEdges(v);
		return v;
	}

	private void graphDataCacheRemoved(RemovalNotification<Function, FcgData> notification) {
		FcgData data = notification.getValue();
		data.dispose();
	}

	private void setLayout(FunctionCallGraph g) {
		try {
			VisualGraphLayout<FcgVertex, FcgEdge> layout =
				layoutProvider.getLayout(g, TaskMonitor.DUMMY);
			g.setLayout(layout);
			view.setLayoutProvider(layoutProvider);
		}
		catch (CancelledException e) {
			// can't happen as long as we are using the dummy monitor
		}
	}

	private void buildComponent() {

		view = new FcgView();

		view.setVertexClickListener((v, info) -> {

			// double-click happened
			if (!isNavigatbleArea(info)) {
				return false;
			}

			Function f = v.getFunction();
			Address entry = f.getEntryPoint();
			Program p = f.getProgram();
			plugin.handleProviderLocationChanged(new ProgramLocation(p, entry));
			return true; // consume the event
		});

		view.setTooltipProvider(new FcgTooltipProvider());

		JComponent viewComponent = view.getViewComponent();
		component = new JPanel(new BorderLayout());
		component.add(viewComponent, BorderLayout.CENTER);
	}

	private boolean isNavigatbleArea(VertexMouseInfo<FcgVertex, FcgEdge> info) {

		Component clickedComponent = info.getClickedComponent();
		if (clickedComponent instanceof JButton) {
			// buttons are for pressing, not navigation
			return false;
		}

		// Don't allow navigation too close to the edges.  This prevents accidental navigation
		// when the user is near a button or another vertex.
		int buffer = 10;
		MouseEvent e = info.getTranslatedMouseEvent();
		Point p = e.getPoint();
		if (p.x < buffer || p.y < buffer) {
			// too close to start
			return false;
		}

		Rectangle bounds = clickedComponent.getBounds();
		if (bounds.width - p.x < buffer || bounds.height - p.y < buffer) {
			// too close to end
			return false;
		}

		return true;
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	@Override
	public void dispose() {
		dataFactory.dispose();
		graphData.dispose();
		super.dispose();
	}

	@Override
	public Class<?> getContextType() {
		// force the window to add the navigation buttons
		return NavigationActionContext.class;
	}

	FunctionCallGraph getGraph() {
		if (graphData.hasResults()) {
			return graphData.getGraph();
		}
		return null;
	}

	void setVertexClickListener(VertexClickListener<FcgVertex, FcgEdge> l) {
		view.setVertexClickListener(l);
	}

	private void createLayouts() {

		//
		// Add some Jung layouts for users to try
		//
		layouts.addAll(JungLayoutProviderFactory.createLayouts());

		// the specialized layout
		layouts.add(defaultLayoutProvider);
		layoutProvider = defaultLayoutProvider;
	}

	private void createActions() {

		addLayoutAction();

		DockingAction collapseIn = new CollapseAction("Hide Incoming Edges", IN);
		DockingAction collapseOut = new CollapseAction("Hide Outgoing Edges", OUT);

		DockingAction expandIn = new ExpandAction("Show Incoming Edges", IN);
		DockingAction expandOut = new ExpandAction("Show Outgoing Edges", OUT);

		DockingAction collapseLevelIn = new CollapseLevelAction("Hide Incoming Level Edges", IN);
		DockingAction collapseLevelOut = new CollapseLevelAction("Hide Outgoing Level Edges", OUT);

		DockingAction expandLevelIn = new ExpandLevelAction("Show Incoming Level Edges", IN);
		DockingAction expandLevelOut = new ExpandLevelAction("Show Outgoing Level Edges", OUT);

		// ExpandLevelAction

		addLocalAction(collapseIn);
		addLocalAction(collapseOut);
		addLocalAction(collapseLevelIn);
		addLocalAction(collapseLevelOut);
		addLocalAction(expandIn);
		addLocalAction(expandOut);
		addLocalAction(expandLevelIn);
		addLocalAction(expandLevelOut);

		navigateIncomingToggleAction =
			new ToggleDockingAction("Navigate on Incoming Location Changes", plugin.getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					// handled later as we receive events
				}

				@Override
				public void setSelected(boolean newValue) {
					super.setSelected(newValue);

					if (isSelected()) {
						locationChanged(plugin.getCurrentLocation());
					}
				}
			};

		navigateIncomingToggleAction.setSelected(true);
		navigateIncomingToggleAction.setToolBarData(
			new ToolBarData(Icons.NAVIGATE_ON_INCOMING_EVENT_ICON, TOOLBAR_GROUP_A));
		navigateIncomingToggleAction.setDescription(HTMLUtilities.toHTML(
			"Incoming Navigation<br><br>Toggle <b>On</b>  - change the graphed " +
				"function on Listing navigation events" +
				"<br>Toggled <b>Off</b> - don't change the graph on Listing navigation events"));
		navigateIncomingToggleAction.setHelpLocation(
			new HelpLocation(plugin.getName(), "Navigation_Incoming"));
		addLocalAction(navigateIncomingToggleAction);

		DockingAction graphFunctionAction =
			new DockingAction("Graph Node Function Calls", plugin.getName()) {

				@Override
				public void actionPerformed(ActionContext context) {
					VgVertexContext<FcgVertex> vContext = getVertexContext(context);
					FcgVertex v = vContext.getVertex();
					setFunction(v.getFunction());
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					VgVertexContext<FcgVertex> vContext = getVertexContext(context);
					if (vContext == null) {
						return false;
					}

					FcgVertex v = vContext.getVertex();
					Function function = v.getFunction();
					Function graphedFunction = graphData.getFunction();

					boolean isEnabled = !function.equals(graphedFunction);
					if (isEnabled) {
						setPopupMenuData(
							new MenuData(new String[] { "Graph '" + function.getName() + "'" },
								MENU_GROUP_GRAPH));
					}
					return isEnabled;
				}
			};

		graphFunctionAction.setPopupMenuData(
			new MenuData(new String[] { "Graph Function" }, MENU_GROUP_GRAPH));
		addLocalAction(graphFunctionAction);

	}

	private Collection<FcgEdge> getGraphEdges(FcgVertex v, FcgDirection direction) {

		FunctionCallGraph graph = graphData.getGraph();
		if (direction == IN) {
			return graph.getInEdges(v);
		}
		return graph.getOutEdges(v);
	}

	// returns edges that we know about, but may not be in the graph
	private Set<FcgEdge> getModelEdges(Iterable<FcgVertex> vertices, FcgLevel level,
			Predicate<FcgEdge> filter) {

		FcgDirection direction = level.getDirection();
		if (direction == IN) {
			return getIncomingEdges(vertices, level, filter);
		}
		return getOutgoingEdges(vertices, level, filter);
	}

	private VgVertexContext<FcgVertex> getVertexContext(ActionContext c) {
		if (!(c instanceof VgVertexContext)) {
			return null;
		}

		@SuppressWarnings("unchecked")
		VgVertexContext<FcgVertex> vContext = (VgVertexContext<FcgVertex>) c;
		return vContext;
	}

	//==================================================================================================
	// Layout Methods
	//==================================================================================================

	/*package*/ static final String RELAYOUT_GRAPH_ACTION_NAME = "Relayout Graph";

	private void addLayoutAction() {

		DockingAction resetGraphAction = new DockingAction("Reset Graph", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				int choice = OptionDialog.showYesNoDialog(getComponent(), "Reset Graph?",
					"<html>Erase all vertex position information?");
				if (choice != OptionDialog.YES_OPTION) {
					return;
				}

				rebuildCurrentGraph();
			}
		};
		resetGraphAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON));
		resetGraphAction.setDescription(
			"<html>Resets the graph--All positioning will be <b>lost</b>");
		resetGraphAction.setHelpLocation(
			new HelpLocation("FunctionCallGraphPlugin", "Relayout_Graph"));

		addLocalAction(resetGraphAction);

		MultiStateDockingAction<LayoutProvider<FcgVertex, FcgEdge, FunctionCallGraph>> layoutAction =
			new MultiStateDockingAction<LayoutProvider<FcgVertex, FcgEdge, FunctionCallGraph>>(
				RELAYOUT_GRAPH_ACTION_NAME, plugin.getName()) {

				@Override
				protected void doActionPerformed(ActionContext context) {
					// this callback is when the user clicks the button
					LayoutProvider<FcgVertex, FcgEdge, FunctionCallGraph> currentUserData =
						getCurrentUserData();
					changeLayout(currentUserData);
				}

				@Override
				public void actionStateChanged(
						ActionState<LayoutProvider<FcgVertex, FcgEdge, FunctionCallGraph>> newActionState,
						EventTrigger trigger) {
					changeLayout(newActionState.getUserData());
				}
			};
		layoutAction.setGroup(TOOLBAR_GROUP_B);

		addLayoutProviders(layoutAction);

		// This action is for development/debug only
		// addLocalAction(layoutAction);
	}

	private void addLayoutProviders(
			MultiStateDockingAction<LayoutProvider<FcgVertex, FcgEdge, FunctionCallGraph>> layoutAction) {

		for (LayoutProvider<FcgVertex, FcgEdge, FunctionCallGraph> l : layouts) {
			layoutAction.addActionState(new ActionState<>(l.getLayoutName(), l.getActionIcon(), l));
		}

		layoutAction.setCurrentActionStateByUserData(defaultLayoutProvider);
	}

	private void changeLayout(LayoutProvider<FcgVertex, FcgEdge, FunctionCallGraph> provider) {

		this.layoutProvider = provider;
		if (isVisible()) { // this method can be called while building--ignore that
			rebuildCurrentGraph();
		}
	}

	private Iterable<FcgVertex> getVerticesByLevel(FcgLevel level) {
		FunctionCallGraph graph = graphData.getGraph();
		return graph.getVerticesByLevel(level);
	}

	private void trackFunctionEdges(FcgVertex v) {

		Function f = v.getFunction();
		FunctionEdgeCache edgeCache = graphData.getFunctionEdgeCache();
		if (edgeCache.isTracked(f)) {
			return; // already tracked
		}

		edgeCache.setTracked(f);

		Set<Function> calling = f.getCallingFunctions(TaskMonitor.DUMMY);
		int count = calling.size();
		if (count > MAX_REFERENCES) {
			// this seemed noisy
			// setStatusMessage("Too many incoming references to display - " + f.getName());
			v.setTooManyIncomingReferences(true);
			v.setHasIncomingReferences(true);
		}
		else {

			trackFunctionIncomingEdges(v, calling);
			v.setHasIncomingReferences(!calling.isEmpty());
		}

		Set<Function> called = f.getCalledFunctions(TaskMonitor.DUMMY);
		count = called.size();
		if (count > MAX_REFERENCES) {
			// this seemed noisy
			// setStatusMessage("Too many outgoing references to display - " + f.getName());
			v.setTooManyOutgoingReferences(true);
			v.setHasOutgoingReferences(true);
		}
		else {
			trackFunctionOutgoingEdges(v, called);
			v.setHasOutgoingReferences(!called.isEmpty());
		}
	}

	private void trackFunctionOutgoingEdges(FcgVertex v, Set<Function> calledFunctions) {

		FunctionEdgeCache edgeCache = graphData.getFunctionEdgeCache();
		Function f = v.getFunction();
		for (Function callee : calledFunctions) {
			edgeCache.get(f).add(new FunctionEdge(f, callee));
		}
	}

	private void trackFunctionIncomingEdges(FcgVertex v, Set<Function> callingFunctions) {

		FunctionEdgeCache edgeCache = graphData.getFunctionEdgeCache();

		Function f = v.getFunction();
		for (Function caller : callingFunctions) {
			edgeCache.get(f).add(new FunctionEdge(caller, f));
		}
	}

//==================================================================================================
// Expand/Collapse Methods
//==================================================================================================	

	/*
	 * 									Notes
	 * 
	 * To expand a node we need to know or calculate:
	 * 		-the clicked node (the source)
	 * 		-all other nodes on the same level as the clicked node (the siblings)
	 * 		-the outgoing nodes of the source node (the new nodes)
	 * 		-the x,y positions of the nodes being added
	 * 			-the siblings of the new nodes, even if not visible
	 * 		-any edges between the new nodes and other existing nodes other than the source
	 *
	 *  The above will be used to layout the new nodes and to animate the new nodes and edges
	 */

	private void expand(FcgVertex source, FcgDirection direction) {
		FcgLevel level = source.getLevel();
		expand(CollectionUtils.asIterable(source), level, direction);
	}

	private void expand(Iterable<FcgVertex> sources, FcgLevel sourceLevel, FcgDirection direction) {

		// remove any non-expandable vertices
		sources = IterableUtils.filteredIterable(sources, v -> v.canExpand());
		if (IterableUtils.isEmpty(sources)) {
			return;
		}

		FcgLevel expandingLevel = sourceLevel.child(direction);

		Set<FcgEdge> newEdges = getModelEdges(sources, expandingLevel, edgeNotInGraphFilter);

		// Need all vertices from the source level, as well as their edges.  
		// This is used to correctly layout the vertices we are adding.  This way, if we 
		// later add the sibling vertices, they will be in the correct spot, without clipping.
		Iterable<FcgVertex> sourceSiblings = getVerticesByLevel(sourceLevel);
		Set<FcgEdge> parentLevelEdges = getModelEdges(sourceSiblings, expandingLevel, unfiltered);

		Set<FcgVertex> newVertices = toVertices(newEdges, direction, vertexInGraphFilter.negate());
		boolean isIncoming = direction == IN;
		FcgExpandingVertexCollection collection =
			new FcgExpandingVertexCollection(sources, sourceLevel, expandingLevel, newVertices,
				newEdges, parentLevelEdges, isIncoming, view.getPrimaryGraphViewer());

		doExpand(collection);

		markExpanded(sources, direction, true);
	}

	private void markExpanded(Iterable<FcgVertex> vertices, FcgDirection direction,
			boolean expanded) {

		if (direction == IN) {
			markInsExpanded(vertices, expanded);
		}
		else {
			markOutsExpanded(vertices, expanded);
		}

		component.repaint();
	}

	private void markInsExpanded(Iterable<FcgVertex> vertices, boolean expanded) {

		for (FcgVertex v : vertices) {
			if (expanded != v.isIncomingExpanded()) {
				v.setIncomingExpanded(expanded);
			}
		}
	}

	private void markOutsExpanded(Iterable<FcgVertex> vertices, boolean expanded) {

		for (FcgVertex v : vertices) {
			if (expanded != v.isOutgoingExpanded()) {
				v.setOutgoingExpanded(expanded);
			}
		}
	}

	private void collapseLevel(FcgLevel level, FcgDirection direction) {

		FcgLevel collapseLevel = level.child(direction);
		Iterable<FcgVertex> toRemove = getVerticesAtOrGreaterThan(collapseLevel);

		// Note: we must collect the vertices before deleting to avoid concurrent modification
		Set<FcgVertex> set = util.CollectionUtils.asSet(toRemove.iterator());
		FunctionCallGraph graph = graphData.getGraph();
		graph.removeVertices(set);
		component.repaint();

		updateTitle();

		Iterable<FcgVertex> sources = graph.getVerticesByLevel(level);
		markExpanded(sources, direction, false);
	}

	private void collapse(FcgVertex v, FcgDirection direction) {

		// copy to avoid ConcurrentModificationExceptions when we remove
		Collection<FcgEdge> edges = new HashSet<>(getGraphEdges(v, direction));
		FunctionCallGraph graph = graphData.getGraph();
		for (FcgEdge e : edges) {

			FcgVertex other = getOtherEnd(v, e);
			if (isDependent(v, other, e)) {
				graph.removeEdge(e);

				collapse(other, direction);
				removeFromGraph(other);
			}
		}

		markExpanded(CollectionUtils.asIterable(v), direction, false);
	}

	private FcgVertex getOtherEnd(FcgVertex v, FcgEdge e) {
		FcgVertex start = e.getStart();
		if (v.equals(start)) {
			return e.getEnd();
		}
		return start;
	}

	private boolean isDependent(FcgVertex parent, FcgVertex other, FcgEdge e) {
		FcgLevel parentLevel = parent.getLevel();
		FcgLevel otherLevel = other.getLevel();
		if (!parentLevel.isParentOf(otherLevel)) {
			// the other vertex must be in the child level to be a dependent 
			return false;
		}

		// At this point we have met the criteria for being a dependent.  However, if another
		// vertex at the parent level points to 'other', then 'other' is also a dependent of
		// that vertex, thus making 'other' not dependent only upon the given vertex.
		FunctionCallGraph g = graphData.getGraph();
		Collection<FcgEdge> ins = g.getInEdges(other);
		for (FcgEdge inEdge : ins) {
			FcgVertex start = inEdge.getStart();
			if (start.equals(parent)) {
				continue;
			}

			FcgLevel inLevel = start.getLevel();
			if (!inLevel.equals(parentLevel)) {
				continue; // not our level; don't care 
			}

			// The 'start' vertex is at the same level as 'parent'.  If it is expanded, then
			// it can be in charge; if it is collapsed, then it is only showing the edge until
			// the node in charge closes it's edges
			if (start.isExpanded()) {
				return false; // 'start' can be in charge
			}
		}
		return true;
	}

	private void removeFromGraph(FcgVertex v) {
		// not sure if there is anything else we need to do here
		FunctionCallGraph g = graphData.getGraph();
		g.removeVertex(v);
		component.repaint();
	}

	private Set<FcgEdge> getIncomingEdges(Iterable<FcgVertex> vertices, FcgLevel level,
			Predicate<FcgEdge> filter) {

		Map<Function, FcgVertex> newVertexCache = new HashMap<>();
		Set<FcgEdge> result = new HashSet<>();
		for (FcgVertex source : vertices) {
			Function f = source.getFunction();
			Iterable<Function> functions = getCallingFunctions(f);
			Set<FcgVertex> callers = toVertices(functions, level, newVertexCache);
			for (FcgVertex caller : callers) {
				FcgEdge e = getOrCreateEdge(caller, source);
				if (!filter.test(e)) {
					continue;
				}
				result.add(e);
			}
		}
		return result;
	}

	private FcgEdge getOrCreateEdge(FcgVertex start, FcgVertex end) {

		FunctionCallGraph graph = graphData.getGraph();
		Iterable<FcgEdge> edges = graph.getEdges(start, end);
		FcgEdge e = CollectionUtils.any(edges);
		if (e != null) {
			return e;
		}
		return new FcgEdge(start, end);
	}

	private Iterable<Function> getCallingFunctions(Function f) {

		FunctionEdgeCache edgeCache = graphData.getFunctionEdgeCache();

		// all functions should be registered when the vertices are created
		SystemUtilities.assertTrue(edgeCache.isTracked(f), "Function not tracked in cache");

		Set<FunctionEdge> edges = edgeCache.get(f);
		Iterable<FunctionEdge> filtered =
			IterableUtils.filteredIterable(edges, e -> isCalledFunction(f, e));
		Iterable<Function> functions =
			IterableUtils.transformedIterable(filtered, e -> e.getStart());
		return functions;
	}

	private Iterable<Function> getCallerFunctions(Function f) {

		FunctionEdgeCache edgeCache = graphData.getFunctionEdgeCache();

		// all functions should be registered when the vertices are created
		SystemUtilities.assertTrue(edgeCache.isTracked(f), "Function not tracked in cache");

		Set<FunctionEdge> edges = edgeCache.get(f);
		Iterable<FunctionEdge> filtered =
			IterableUtils.filteredIterable(edges, e -> isCallingFunction(f, e));
		Iterable<Function> functions = IterableUtils.transformedIterable(filtered, e -> e.getEnd());
		return functions;
	}

	private boolean isCallingFunction(Function f, FunctionEdge e) {
		Function start = e.getStart();
		return start.equals(f);
	}

	private boolean isCalledFunction(Function f, FunctionEdge e) {
		Function end = e.getEnd();
		return end.equals(f);
	}

	private Set<FcgVertex> toStartVertices(Iterable<FcgEdge> edges, Predicate<FcgVertex> filter) {
		//@formatter:off 
		return CollectionUtils
			.asStream(edges)
			.map(e -> e.getStart())
			.filter(filter)
			.collect(Collectors.toSet())
			;
		//@formatter:on
	}

	private Set<FcgVertex> toVertices(Iterable<FcgEdge> edges, FcgDirection direction,
			Predicate<FcgVertex> filter) {
		return direction == IN ? toStartVertices(edges, filter) : toEndVertices(edges, filter);
	}

	private Set<FcgVertex> toEndVertices(Iterable<FcgEdge> edges, Predicate<FcgVertex> filter) {
		//@formatter:off
		return CollectionUtils
				.asStream(edges)
				.map(e -> e.getEnd())
				.filter(filter)
				.collect(Collectors.toSet())
				;
		//@formatter:on
	}

	private Set<FcgEdge> getOutgoingEdges(Iterable<FcgVertex> vertices, FcgLevel level,
			Predicate<FcgEdge> filter) {

		Map<Function, FcgVertex> newVertexCache = new HashMap<>();
		Set<FcgEdge> result = new HashSet<>();
		for (FcgVertex source : vertices) {
			Function f = source.getFunction();
			Iterable<Function> functions = getCallerFunctions(f);
			Set<FcgVertex> callees = toVertices(functions, level, newVertexCache);
			for (FcgVertex callee : callees) {
				FcgEdge e = getOrCreateEdge(source, callee);
				if (!filter.test(e)) {
					continue;
				}
				result.add(e);
			}
		}
		return result;
	}

	private Iterable<FcgVertex> getVerticesAtOrGreaterThan(FcgLevel level) {
		List<Iterable<FcgVertex>> result = new ArrayList<>();
		FunctionCallGraph graph = graphData.getGraph();
		FcgLevel greatestLevel = graph.getLargestLevel(level.getDirection());
		FcgLevel currentLevel = level;
		while (currentLevel.getRow() <= greatestLevel.getRow()) {
			Iterable<FcgVertex> vertices = getVerticesByLevel(currentLevel);
			result.add(vertices);
			currentLevel = currentLevel.child();
		}

		// hand out from greatest to least so that we can close the extremities first 
		Collections.reverse(result);

		@SuppressWarnings("unchecked")
		Iterable<FcgVertex>[] array = result.toArray(new Iterable[result.size()]);
		return IterableUtils.chainedIterable(array);
	}

	private void doExpand(FcgExpandingVertexCollection collection) {

		// note: we must do this before adding edges, as that will also add vertices and 
		//       we will filter vertices later by those that are not already in the graph		

		Set<FcgVertex> newVertices = collection.getNewVertices();
		FunctionCallGraph graph = graphData.getGraph();
		for (FcgVertex v : newVertices) {  // add vertices now to get incident edges below
			graph.addVertex(v);
		}

		Iterable<FcgEdge> newEdges = collection.getNewEdges();
		for (FcgEdge e : newEdges) { // add all edges, even those where both nodes are in the graph			
			graph.addEdge(e);
		}

		Set<FcgEdge> indirectEdges = new HashSet<>();
		addEdgesToExistingVertices(newVertices, indirectEdges);
		collection.setIndirectEdges(indirectEdges);

		int newEdgeCount = collection.getNewEdgeCount();
		if (newEdgeCount == 0) {
			// this can happen when all edges for the clicked node are already in the graph
			highlightExistingEdges(collection);
			return;
		}

		GraphViewer<FcgVertex, FcgEdge> viewer = view.getPrimaryGraphViewer();
		BowTieExpandVerticesJob job = new BowTieExpandVerticesJob(viewer, collection, true);
		VisualGraphViewUpdater<FcgVertex, FcgEdge> updater = view.getViewUpdater();
		updater.scheduleViewChangeJob(job);

		updateTitle();
	}

	private void highlightExistingEdges(FcgExpandingVertexCollection collection) {

		GraphViewer<FcgVertex, FcgEdge> viewer = view.getPrimaryGraphViewer();
		VisualGraphViewUpdater<FcgVertex, FcgEdge> updater = view.getViewUpdater();

		Iterable<FcgVertex> sources = collection.getSources();
		FcgVertex source = CollectionUtils.any(sources);
		FcgLevel level = source.getLevel();
		Set<FcgEdge> existingEdges = getModelEdges(sources, level, unfiltered);
		FcgEmphasizeEdgesJob job = new FcgEmphasizeEdgesJob(viewer, existingEdges);
		updater.scheduleViewChangeJob(job);
	}

	/**
	 * Called when new vertices are added to the graph to ensure that known edges between any
	 * level of the graph get added as the associated vertices are added to the graph.  This 
	 * is needed because we don't add all known edges for a single vertex when it is added, as 
	 * its associated vertex may not yet be in the graph.   Calling this method ensures that as
	 * vertices appear, the edges are added.
	 * 
	 * @param newVertices the vertices being added to the graph
	 * @param newEdges the set to which should be added any new edges being added to the graph 
	 */
	private void addEdgesToExistingVertices(Iterable<FcgVertex> newVertices,
			Set<FcgEdge> newEdges) {

		FunctionCallGraph graph = graphData.getGraph();
		FunctionEdgeCache cache = graphData.getFunctionEdgeCache();
		for (FcgVertex v : newVertices) {
			Function f = v.getFunction();
			Set<FunctionEdge> edges = cache.get(f);
			for (FunctionEdge e : edges) {
				Function start = e.getStart();
				Function end = e.getEnd();
				FcgVertex v1 = graph.getVertex(start);
				FcgVertex v2 = graph.getVertex(end);
				if (v1 == null || v2 == null) {
					continue;
				}

				if (!graph.containsEdge(v1, v2)) {
					FcgEdge newEdge = new FcgEdge(v1, v2);
					graph.addEdge(newEdge);
					newEdges.add(newEdge);
				}
			}
		}
	}

	private Set<FcgVertex> toVertices(Iterable<Function> callees, FcgLevel level,
			Map<Function, FcgVertex> newVertexCache) {

		//
		//						Unusual Code Alert
		// We wish to always use the same vertex *instance* across edges that we are 
		// creating.  If the vertex is already in the graph, then that will happen as we get it
		// from the graph.  However, if the function does not have a vertex in the graph, then
		// it must be created.  Cache the vertices we retrieve here, whether exiting or created,
		// so that we always use the same instance as we map functions to vertices.
		//

		//@formatter:off
		return CollectionUtils.asStream(callees)		
		    .map(f -> {
			  
			    if (newVertexCache.containsKey(f)) {
			    	return newVertexCache.get(f);
			    }
			  
			    FcgVertex v = getOrCreateVertex(f, level);
			    newVertexCache.put(f, v);
			    return v;
		    })
		    .collect(Collectors.toSet())
		    ;
		//@formatter:on
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class ExpansionListener implements FcgVertexExpansionListener {

		@Override
		public void toggleIncomingVertices(FcgVertex v) {

			boolean expanded = v.isIncomingExpanded(); // graphContainsNextLevelVertices(v, IN);
			if (expanded) {
				collapse(v, IN);
			}
			else {
				expand(v, IN);
			}
		}

		@Override
		public void toggleOutgoingVertices(FcgVertex v) {
			boolean expanded = v.isOutgoingExpanded(); // graphContainsNextLevelVertices(v, OUT);
			if (expanded) {
				collapse(v, OUT);
			}
			else {
				expand(v, OUT);
			}
		}
	}

	private abstract class AbstractCollapseAction extends DockingAction {
		protected FcgDirection direction;

		AbstractCollapseAction(String actionName, FcgDirection direction) {
			super(actionName, plugin.getName());
			this.direction = direction;

			setPopupMenuData(new MenuData(new String[] { actionName }, MENU_GROUP_EXPAND));
			setHelpLocation(new HelpLocation("FunctionCallGraphPlugin", "Expand_Collapse"));
		}

		abstract void collapseFromContext(VgVertexContext<FcgVertex> context);

		@Override
		public void actionPerformed(ActionContext context) {

			VgVertexContext<FcgVertex> vContext = getVertexContext(context);
			collapseFromContext(vContext);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {

			VgVertexContext<FcgVertex> vContext = getVertexContext(context);
			if (vContext == null) {
				return false;
			}

			FcgVertex v = vContext.getVertex();
			boolean expanded = direction == IN ? v.isIncomingExpanded() : v.isOutgoingExpanded();
			if (!expanded) {
				return false; // already collapsed			
			}

			if (!isMyDirection(v.getLevel())) {
				// only enable on incoming or outgoing, depending upon the subclass
				return false;
			}

			return true;
		}

		boolean isMyDirection(FcgLevel level) {
			return level.getDirection() == direction;
		}
	}

	private class CollapseAction extends AbstractCollapseAction {

		CollapseAction(String actionName, FcgDirection direction) {
			super(actionName, direction);
		}

		@Override
		void collapseFromContext(VgVertexContext<FcgVertex> context) {
			FcgVertex v = context.getVertex();
			collapse(v, direction);
		}
	}

	private class CollapseLevelAction extends AbstractCollapseAction {

		CollapseLevelAction(String actionName, FcgDirection direction) {
			super(actionName, direction);
		}

		@Override
		void collapseFromContext(VgVertexContext<FcgVertex> context) {
			FcgVertex v = context.getVertex();
			FcgLevel level = v.getLevel();
			collapseLevel(level, direction);
		}

		@Override
		boolean isMyDirection(FcgLevel level) {
			if (level.getDirection() == FcgDirection.IN_AND_OUT) {
				return true;
			}
			return level.getDirection() == direction;
		}
	}

	private abstract class AbstractExpandAction extends DockingAction {

		protected FcgDirection direction;

		AbstractExpandAction(String actionName, FcgDirection direction) {
			super(actionName, plugin.getName());
			this.direction = direction;

			setPopupMenuData(new MenuData(new String[] { actionName }, MENU_GROUP_EXPAND));
			setHelpLocation(new HelpLocation("FunctionCallGraphPlugin", "Expand_Collapse"));
		}

		abstract void expandFromContext(VgVertexContext<FcgVertex> context);

		abstract boolean isExpandable(FcgVertex v);

		@Override
		public void actionPerformed(ActionContext context) {
			VgVertexContext<FcgVertex> vContext = getVertexContext(context);
			expandFromContext(vContext);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {

			VgVertexContext<FcgVertex> vContext = getVertexContext(context);
			if (vContext == null) {
				return false;
			}

			FcgVertex v = vContext.getVertex();
			boolean isExpandable = isExpandable(v);
			if (!isExpandable) {
				return false; // already expanded			
			}

			if (!isMyDirection(v.getLevel())) {
				// only enable on incoming or outgoing, depending upon the subclass
				return false;
			}

			return true;
		}

		boolean isMyDirection(FcgLevel level) {
			return level.getDirection() == direction;
		}
	}

	private class ExpandAction extends AbstractExpandAction {

		ExpandAction(String actionName, FcgDirection direction) {
			super(actionName, direction);
		}

		@Override
		void expandFromContext(VgVertexContext<FcgVertex> context) {
			FcgVertex v = context.getVertex();
			expand(v, direction);
		}

		@Override
		boolean isExpandable(FcgVertex v) {
			return v.canExpand();
		}
	}

	private class ExpandLevelAction extends AbstractExpandAction {

		ExpandLevelAction(String actionName, FcgDirection direction) {
			super(actionName, direction);
		}

		@Override
		void expandFromContext(VgVertexContext<FcgVertex> context) {

			FcgVertex v = context.getVertex();
			FcgLevel level = v.getLevel();
			Iterable<FcgVertex> vertices = getVerticesByLevel(v.getLevel());
			expand(vertices, level, direction);
		}

		@Override
		boolean isMyDirection(FcgLevel level) {
			if (level.getDirection() == FcgDirection.IN_AND_OUT) {
				return true;
			}
			return level.getDirection() == direction;
		}

		@Override
		boolean isExpandable(FcgVertex vertex) {
			Iterable<FcgVertex> vertices = getVerticesByLevel(vertex.getLevel());
			return CollectionUtils.asStream(vertices).anyMatch(v -> v.canExpand());
		}
	}
}
