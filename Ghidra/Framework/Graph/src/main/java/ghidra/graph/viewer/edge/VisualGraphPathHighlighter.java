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
package ghidra.graph.viewer.edge;

import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.function.Supplier;

import docking.DockingWindowManager;
import generic.concurrent.GThreadPool;
import ghidra.graph.*;
import ghidra.graph.algo.ChkDominanceAlgorithm;
import ghidra.graph.algo.ChkPostDominanceAlgorithm;
import ghidra.graph.graphs.GroupingVisualGraph;
import ghidra.graph.viewer.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.CallbackAccumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;
import utility.function.Callback;

/**
 * A class that calculates flow between vertices and then triggers that flow to be painted
 * in the UI.
 * 
 * <P><B><U>Threading Policy:</U></B>  Some operations use algorithms that slow down, depending
 * upon the graph size.  Further, some of these algorithms may not even complete.  To keep the
 * graph responsive, this class will perform its work <I>in the future</I>.   The work we 
 * wish to do is further complicated by these requirements:
 * <UL>
 * 	<LI>Some data should be calculated only as needed, to avoid excessive work</LI>
 * 	<LI>Many tasks depend on data to be calculated before they can perform their algorithm</LI>
 * 	<LI>Results must be cached for speed, but may cleared as the graph is mutated</LI>
 *  <LI>Algorithms must not block the UI thread</LI>
 *  <LI>Related actions (i.e., hover vs. selection) should cancel any pending action, but not 
 *      unrelated actions (e.g., a new hover request should cancel a pending hover update)
 * </UL>
 * 
 * Based on these requirements, we need to use multi-threading.  Further complicating the need
 * for multi-threading is that some operations depending on lazy-loaded data.  Finally, we 
 * have different types of actions, hovering vs. selecting a vertex, which should override 
 * previous related requests.   To accomplish this we use:
 * <UL>
 * 	<LI>{@link CompletableFuture} - to lazy-load and cache required algorithm data</LI>
 * 	<LI>{@link RunManager}s - to queue requests so that new requests cancel old ones.  A 
 *      different Run Manager is used for each type of request.</LI>
 * </UL>
 * 		
 * <P><B><U>Naming Conventions:</U></B>  There are many methods in this class, called from 
 * different threads.   For simplicity, we use the following conventions: 
 * <UL>
 * 	<LI><CODE>fooAsync</CODE> - methods ending in <B>Async</B> indicate that they are to be 
 *                              called from a background thread.</LI>
 *  <LI><CODE>fooSwing</CODE> - methods ending in <B>Swing</B> indicate that they are to be 
 *                              called from the Swing thread.</LI>                             
 * 	<LI>*All public methods are assumed to be called on the Swing thread</LI>
 * </UL>
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class VisualGraphPathHighlighter<V extends VisualVertex, E extends VisualEdge<V>> {

	// Note: dominance is usually calculated in less than a second; if the timeout is reached,
	//       then we have a degenerate case or too large a graph
	private static final int ALGORITHM_TIMEOUT = 5;

	private PathHighlightMode vertexFocusMode = PathHighlightMode.OFF;
	private PathHighlightMode vertexHoverMode = PathHighlightMode.OFF;

	private Map<V, Set<E>> forwardFlowEdgeCache = new HashMap<>();
	private Map<V, Set<E>> reverseFlowEdgeCache = new HashMap<>();
	private Map<V, Set<E>> forwardScopedFlowEdgeCache = new HashMap<>();
	private Map<V, Set<E>> reverseScopedFlowEdgeCache = new HashMap<>();
	private VisualGraph<V, E> graph;

	private RunManager hoverRunManager =
		new RunManager(GraphViewerUtils.GRAPH_DECORATOR_THREAD_POOL_NAME, null);
	private RunManager focusRunManager =
		new RunManager(GraphViewerUtils.GRAPH_DECORATOR_THREAD_POOL_NAME, null);

	private CompletableFuture<ChkDominanceAlgorithm<V, E>> dominanceFuture;
	private CompletableFuture<ChkDominanceAlgorithm<V, E>> postDominanceFuture;
	private CompletableFuture<Circuits> circuitFuture;

	private PathHighlightListener listener = isHover -> {
		// stub
	};

	private PathHighlighterWorkPauser workPauser = () -> false;

	private SwingUpdateManager focusedVertexUpdater =
		new SwingUpdateManager(() -> doUpdateFocusedVertex());

	public VisualGraphPathHighlighter(VisualGraph<V, E> graph, PathHighlightListener listener) {
		this.graph = graph;
		if (listener != null) {
			this.listener = listener;
		}
	}

	/**
	 * Sets the callback that signals when this path highlighter should not be performing any
	 * work
	 * 
	 * @param pauser the callback that returns a boolean of true when this class should pause
	 *        its work.
	 */
	public void setWorkPauser(PathHighlighterWorkPauser pauser) {
		if (pauser != null) {
			this.workPauser = pauser;
		}
	}

	private Executor getGraphExecutor() {
		GThreadPool pool =
			GThreadPool.getSharedThreadPool(GraphViewerUtils.GRAPH_DECORATOR_THREAD_POOL_NAME);
		return pool.getExecutor();
	}

	private CompletableFuture<ChkDominanceAlgorithm<V, E>> lazyCreateDominaceFuture() {

		// lazy-load
		if (dominanceFuture != null) {
			return dominanceFuture;
		}

		// we use an executor to restrict thread usage by the Graph API
		Executor executor = getGraphExecutor();
		dominanceFuture = CompletableFuture.supplyAsync(() -> {

			// this operation is fast enough that it shouldn't timeout, but just in case...
			TaskMonitor timeoutMonitor = TimeoutTaskMonitor.timeoutIn(ALGORITHM_TIMEOUT,
				TimeUnit.SECONDS, new TaskMonitorAdapter(true));

			GDirectedGraph<V, E> dominanceGraph = getDominanceGraph(graph, true);
			if (dominanceGraph == null) {
				Msg.debug(this, "No sources found for graph; cannot calculate dominance: " +
					graph.getClass().getSimpleName());
				return null;
			}

			try {
				// note: calling the constructor performs the work
				return new ChkDominanceAlgorithm<>(dominanceGraph, timeoutMonitor);
			}
			catch (CancelledException e) {
				// shouldn't happen
				Msg.debug(VisualGraphPathHighlighter.this,
					"Domiance calculation timed-out for " + graph.getClass().getSimpleName());
			}
			return null;
		}, executor);
		return dominanceFuture;
	}

	protected GDirectedGraph<V, E> getDominanceGraph(VisualGraph<V, E> visualGraph,
			boolean forward) {

		Set<V> sources = GraphAlgorithms.getSources(visualGraph);
		if (!sources.isEmpty()) {
			return visualGraph;
		}

		return null;
	}

	private CompletableFuture<ChkDominanceAlgorithm<V, E>> lazyCreatePostDominanceFuture() {

		// lazy-load
		if (postDominanceFuture != null) {
			return postDominanceFuture;
		}

		Executor executor = getGraphExecutor();
		postDominanceFuture = CompletableFuture.supplyAsync(() -> {

			// this operation is fast enough that it shouldn't timeout, but just in case...
			TaskMonitor timeoutMonitor = TimeoutTaskMonitor.timeoutIn(ALGORITHM_TIMEOUT,
				TimeUnit.SECONDS, new TaskMonitorAdapter(true));

			try {
				// note: calling the constructor performs the work
				return new ChkPostDominanceAlgorithm<>(graph, timeoutMonitor);
			}
			catch (CancelledException e) {
				// shouldn't happen
				Msg.debug(VisualGraphPathHighlighter.this,
					"Post-domiance calculation timed-out for " + graph.getClass().getSimpleName());
			}
			return null;
		}, executor);
		return postDominanceFuture;
	}

	private CompletableFuture<VisualGraphPathHighlighter<V, E>.Circuits> lazyCreateCircuitFuture() {

		// lazy-load
		if (circuitFuture != null) {
			return circuitFuture;
		}

		Executor executor = getGraphExecutor();
		circuitFuture = CompletableFuture.supplyAsync(() -> {

			// this operation is fast enough that it shouldn't timeout, but just in case...
			TaskMonitor timeoutMonitor = TimeoutTaskMonitor.timeoutIn(ALGORITHM_TIMEOUT,
				TimeUnit.SECONDS, new TaskMonitorAdapter(true));

			Circuits circuits = calculateCircuitsAsync(timeoutMonitor);
			if (!circuits.complete) {
				setStatusTextSwing("Unable to calculate all loops - timed-out");
			}

			return circuits;
		}, executor);
		return circuitFuture;
	}

	private void setStatusTextSwing(String message) {
		DockingWindowManager dwm = DockingWindowManager.getActiveInstance();
		if (dwm != null) {
			dwm.setStatusText(message);
		}
	}

	/**
	 * Signals to this path highlighter that it should stop all background jobs
	 */
	public void stop() {
		hoverRunManager.cancelAllRunnables();
		focusRunManager.cancelAllRunnables();

		if (dominanceFuture != null) {
			dominanceFuture.cancel(true);
		}

		if (postDominanceFuture != null) {
			postDominanceFuture.cancel(true);
		}

		if (circuitFuture != null) {
			circuitFuture.cancel(true);
		}
	}

	public void dispose() {
		hoverRunManager.dispose();
		focusRunManager.dispose();
		clearCacheSwing();
	}

	public boolean isBusy() {
		return hoverRunManager.isInProgress() || focusRunManager.isInProgress();
	}

	public PathHighlightMode getVertexHoverPathHighlightMode() {
		return vertexHoverMode;
	}

	public PathHighlightMode getVertexFocusPathHighlightMode() {
		return vertexFocusMode;
	}

	public void setVertexFocusMode(PathHighlightMode mode) {
		this.vertexFocusMode = Objects.requireNonNull(mode);
		V focusedVertex = graph.getFocusedVertex();
		setFocusedVertex(focusedVertex);
	}

	public void setVertexHoverMode(PathHighlightMode mode) {
		this.vertexHoverMode = Objects.requireNonNull(mode);
		if (vertexHoverMode == PathHighlightMode.OFF) {
			clearHoveredEdgesSwing();
		}
	}

	public void setHoveredVertex(V hoveredVertex) {

		clearHoveredEdgesSwing();

		if (workPauser.isPaused()) {
			return; // hovers are transient, no need to remember the request
		}

		if (hoveredVertex == null) {
			return;
		}

		switch (vertexHoverMode) {
			case IN:
				setInHoveredEdgesSwing(hoveredVertex);
				break;
			case OUT:
				setOutHoveredEdgesSwing(hoveredVertex);
				break;
			case INOUT:
				setInOutHoveredEdgesSwing(hoveredVertex);
				break;
			case CYCLE:
				setVertexCycleHoveredEdgesSwing(hoveredVertex);
				break;
			case SCOPED_FORWARD:
				setForwardScopedFlowHoveredEdgesSwing(hoveredVertex);
				break;
			case SCOPED_REVERSE:
				setReverseScopedFlowHoveredEdgesSwing(hoveredVertex);
				break;
			case PATH:
				V focusedVertex = graph.getFocusedVertex();
				if (focusedVertex != null) {
					setVertexToVertexPathHoveredEdgesSwing(focusedVertex, hoveredVertex);
				}
				break;
			case OFF:
			default:
				break;
		}
	}

	public void setFocusedVertex(V focusedVertex) {

		if (workPauser.isPaused()) {
			focusedVertexUpdater.updateLater(); // redo this later when work is not paused
			return;
		}

		clearFocusedEdgesSwing();
		if (vertexFocusMode == PathHighlightMode.ALLCYCLE) {
			setAllCycleFocusedEdgesSwing();
			return;
		}

		if (focusedVertex == null) {
			return;
		}

		switch (vertexFocusMode) {
			case IN:
				setInFocusedEdges(focusedVertex);
				break;
			case OUT:
				setOutFocusedEdgesSwing(focusedVertex);
				break;
			case INOUT:
				setInOutFocusedEdgesSwing(focusedVertex);
				break;
			case SCOPED_FORWARD:
				setForwardScopedFlowFocusedEdgesSwing(focusedVertex);
				break;
			case SCOPED_REVERSE:
				setReverseScopedFlowFocusedEdgesSwing(focusedVertex);
				break;
			case CYCLE:
				setVertexCycleFocusedEdgesSwing(focusedVertex);
				break;
			case OFF:
			default:
				break;
		}
	}

	private void doUpdateFocusedVertex() {
		V focusedVertex = graph.getFocusedVertex();
		setFocusedVertex(focusedVertex);
	}

	private void clearHoveredEdgesSwing() {
		for (E edge : graph.getEdges()) {
			edge.setInHoveredVertexPath(false);
		}
	}

	private void clearFocusedEdgesSwing() {
		for (E edge : graph.getEdges()) {
			edge.setInFocusedVertexPath(false);
		}
	}

	public void clearEdgeCache() {
		//
		// This call to clear the cache happens due to graph vertex mutations.  The client does 
		// not want outdated edge information that points to removed vertices hanging around.
		// However, the loop information is calculated not on-the-fly, but when the graph is
		// first loaded.  Thus, clearing that will trigger the graph to lose all loop info.  To
		// avoid this, we will update the loop info to reflect the current graph vertex state.
		//
		Set<E> newAllCircuitFlowEdgeCache = new HashSet<>();
		Map<V, Set<E>> newCircuitFlowEdgeCache = new HashMap<>();

		accumulateCircuitEdgesForCurrentStateOfGraphSwing(newAllCircuitFlowEdgeCache,
			newCircuitFlowEdgeCache);

		clearCacheSwing();

		setEdgeCircuitsSwing(newAllCircuitFlowEdgeCache, newCircuitFlowEdgeCache);
	}

//==================================================================================================
// Swing Thread Methods
//==================================================================================================

	private void accumulateCircuitEdgesForCurrentStateOfGraphSwing(Set<E> newAllCircuits,
			Map<V, Set<E>> newCircuitsByVertex) {

		CompletableFuture<Circuits> f = circuitFuture;
		if (f == null || !f.isDone() || f.isCancelled()) {
			return; // no circuits yet calculated
		}

		Circuits circuits = getAsync(circuitFuture); // non-blocking, since we checked above
		accumulateAllCircuitsSwing(circuits, newAllCircuits);
		accumulateVertexCircuitsSwing(circuits, newCircuitsByVertex);
	}

	private void accumulateAllCircuitsSwing(Circuits circuits, Set<E> results) {

		Set<E> edges = circuits.allCircuits;
		for (E e : edges) {
			E currentEdge = ensureEdgeUpToDateSwing(e);
			if (currentEdge != null) {
				// edge is null when the old edge endpoints have both been grouped
				results.add(currentEdge);
			}
		}
	}

	private void accumulateVertexCircuitsSwing(Circuits circuits, Map<V, Set<E>> results) {

		Map<V, Set<E>> circuitsByVertex = circuits.circuitsByVertex;
		Set<Entry<V, Set<E>>> entrySet = circuitsByVertex.entrySet();
		for (Entry<V, Set<E>> entry : entrySet) {
			V v = entry.getKey();

			if (!graph.containsVertex(v)) {
				V newVertex = findMatchingVertexSwing(v);
				if (newVertex == null) {
					// this can happen during grouping operations
					continue;
				}
				v = newVertex;
			}

			HashSet<E> newEdgeSet = new HashSet<>();
			Set<E> oldEdgeSet = entry.getValue();
			for (E e : oldEdgeSet) {
				E currentEdge = ensureEdgeUpToDateSwing(e);
				if (currentEdge != null) {
					// edge is null when the old edge endpoints have both been grouped
					newEdgeSet.add(currentEdge);
				}
			}

			results.put(v, newEdgeSet);
		}
	}

	private E ensureEdgeUpToDateSwing(E edge) {

		V start = edge.getStart();
		V end = edge.getEnd();

		// a 'contains' lookup is faster than the search required by the 'find' below
		boolean containsStart = graph.containsVertex(start);
		boolean containsDestination = graph.containsVertex(end);
		if (containsStart && containsDestination) {
			return edge;
		}

		// At least one of the vertices is no longer in the graph.  Find the equivalent and
		// then get the new edge.
		V newStart = findMatchingVertexSwing(start);
		V newEnd = findMatchingVertexSwing(end);
		return graph.findEdge(newStart, newEnd);
	}

	private V findMatchingVertexSwing(V v) {
		if (!(graph instanceof GroupingVisualGraph)) {
			return v;
		}

		V matchingVertex = ((GroupingVisualGraph<V, E>) graph).findMatchingVertex(v);
		return matchingVertex;
	}

	private void clearCacheSwing() {

		forwardFlowEdgeCache.clear();
		reverseFlowEdgeCache.clear();
		forwardScopedFlowEdgeCache.clear();
		reverseScopedFlowEdgeCache.clear();

		disposeSwing(circuitFuture, Circuits::clear);
		disposeSwing(dominanceFuture, ChkDominanceAlgorithm::clear);
		disposeSwing(postDominanceFuture, ChkDominanceAlgorithm::clear);

		// reset these to compensate for new or removed vertices (but not the circuits, 
		// as they are slow and we can recalculate them)
		dominanceFuture = null;
		postDominanceFuture = null;
	}

	private void setInFocusedEdges(V vertex) {

		Supplier<Set<E>> supplier = () -> getReverseFlowEdgesForVertexAsync(vertex);
		focusRunManager.runNow(new SetFocusedEdgesRunnable(supplier), null);
	}

	private void setOutFocusedEdgesSwing(V vertex) {

		Supplier<Set<E>> supplier = () -> getForwardFlowEdgesForVertexAsync(vertex);
		focusRunManager.runNow(new SetFocusedEdgesRunnable(supplier), null);
	}

	private void setForwardScopedFlowFocusedEdgesSwing(V vertex) {

		Supplier<Set<E>> supplier = () -> getForwardScopedFlowEdgesForVertexAsync(vertex);
		focusRunManager.runNow(new SetFocusedEdgesRunnable(supplier), null);
	}

	private void setReverseScopedFlowFocusedEdgesSwing(V vertex) {

		Supplier<Set<E>> supplier = () -> getReverseScopedFlowEdgesForVertexAsync(vertex);
		focusRunManager.runNow(new SetFocusedEdgesRunnable(supplier), null);
	}

	private void setInOutFocusedEdgesSwing(V vertex) {

		//
		// Select ins and outs, one after the other.
		//
		Supplier<Set<E>> inSupplier = () -> getReverseFlowEdgesForVertexAsync(vertex);
		focusRunManager.runNow(new SetFocusedEdgesRunnable(inSupplier), null);

		Supplier<Set<E>> outSupplier = () -> getForwardFlowEdgesForVertexAsync(vertex);
		focusRunManager.runNext(new SetFocusedEdgesRunnable(outSupplier), null);
	}

	private void setVertexCycleFocusedEdgesSwing(V vertex) {

		Supplier<Set<E>> supplier = () -> getCircuitEdgesAsync(vertex);
		focusRunManager.runNow(new SetFocusedEdgesRunnable(supplier), null);
	}

	private void setAllCycleFocusedEdgesSwing() {

		Supplier<Set<E>> supplier = () -> getAllCircuitFlowEdgesAsync();
		focusRunManager.runNow(new SetFocusedEdgesRunnable(supplier), null);
	}

	private void setInHoveredEdgesSwing(V vertex) {

		Supplier<Set<E>> supplier = () -> getReverseFlowEdgesForVertexAsync(vertex);
		hoverRunManager.runNow(new SetHoveredEdgesRunnable(supplier), null);
	}

	private void setOutHoveredEdgesSwing(V vertex) {

		Supplier<Set<E>> supplier = () -> getForwardFlowEdgesForVertexAsync(vertex);
		hoverRunManager.runNow(new SetHoveredEdgesRunnable(supplier), null);
	}

	private void setForwardScopedFlowHoveredEdgesSwing(V vertex) {

		Supplier<Set<E>> supplier = () -> getForwardScopedFlowEdgesForVertexAsync(vertex);
		hoverRunManager.runNow(new SetHoveredEdgesRunnable(supplier), null);
	}

	private void setReverseScopedFlowHoveredEdgesSwing(V vertex) {

		Supplier<Set<E>> supplier = () -> getReverseScopedFlowEdgesForVertexAsync(vertex);
		hoverRunManager.runNow(new SetHoveredEdgesRunnable(supplier), null);
	}

	private void setInOutHoveredEdgesSwing(V vertex) {

		//
		// Select ins and outs, one after the other.
		//
		Supplier<Set<E>> inSupplier = () -> getReverseFlowEdgesForVertexAsync(vertex);
		hoverRunManager.runNow(new SetHoveredEdgesRunnable(inSupplier), null);

		Supplier<Set<E>> outSupplier = () -> getForwardFlowEdgesForVertexAsync(vertex);
		hoverRunManager.runNext(new SetHoveredEdgesRunnable(outSupplier), null);
	}

	private void setVertexCycleHoveredEdgesSwing(V vertex) {

		Supplier<Set<E>> supplier = () -> getCircuitEdgesAsync(vertex);
		hoverRunManager.runNow(new SetHoveredEdgesRunnable(supplier), null);
	}

	private void setVertexToVertexPathHoveredEdgesSwing(V start, V end) {

		Callback callback = () -> calculatePathsBetweenVerticesAsync(start, end);
		focusRunManager.runNow(new SlowSetHoveredEdgesRunnable(callback), null);

	}

	private void setInFocusedPathOnSwing(Collection<E> edges) {
		edges.forEach(e -> e.setInFocusedVertexPath(true));
		listener.pathHighlightChanged(false);
	}

	private void setInHoverPathOnSwing(Collection<E> edges) {
		edges.forEach(e -> e.setInHoveredVertexPath(true));
		listener.pathHighlightChanged(true);
	}

	private void setEdgeCircuitsSwing(Set<E> allCircuitResults, Map<V, Set<E>> circuitFlowResults) {

		// update the focus mode and then repaint the graph now that we have the needed data
		if (vertexFocusMode == PathHighlightMode.ALLCYCLE) {
			setAllCycleFocusedEdgesSwing();
		}
		else if (vertexFocusMode == PathHighlightMode.CYCLE) {
			V focused = graph.getFocusedVertex();
			setVertexCycleFocusedEdgesSwing(focused);
		}
	}

	private <T> void disposeSwing(CompletableFuture<T> cf, Consumer<T> clearer) {

		if (cf == null) {
			// never loaded
			return;
		}

		if (!cf.isDone()) {
			cf.cancel(true);
			return;
		}

		if (cf.isCompletedExceptionally()) {
			return;
		}

		// clear the contents of the future, as it is acting like a cache
		T result = cf.getNow(null);
		if (result != null) {
			clearer.accept(result);
		}
	}

//==================================================================================================
// Asynchronous Methods (expected to be called in the background)
//==================================================================================================	

	private Set<E> getForwardScopedFlowEdgesForVertexAsync(V v) {
		if (v == null) {
			return null;
		}

		Set<E> flowEdges = forwardScopedFlowEdgeCache.get(v);
		if (flowEdges == null) {
			flowEdges = findForwardScopedFlowAsync(v);
			forwardScopedFlowEdgeCache.put(v, flowEdges);
		}
		return Collections.unmodifiableSet(flowEdges);
	}

	private Set<E> getForwardFlowEdgesForVertexAsync(V v) {
		return getFlowEdgesForVertexAsync(true, forwardFlowEdgeCache, v);
	}

	private Set<E> getReverseFlowEdgesForVertexAsync(V v) {
		return getFlowEdgesForVertexAsync(false, reverseFlowEdgeCache, v);
	}

	private Set<E> getFlowEdgesForVertexAsync(boolean isForward, Map<V, Set<E>> cache, V v) {

		if (v == null) {
			return null;
		}

		Set<E> flowEdges = cache.get(v);
		if (flowEdges == null) {
			flowEdges = new HashSet<>();
			Set<E> pathsToVertex = GraphAlgorithms.getEdgesFrom(graph, v, isForward);
			flowEdges.addAll(pathsToVertex);
			cache.put(v, flowEdges);
		}
		return Collections.unmodifiableSet(flowEdges);
	}

	private Set<E> getAllCircuitFlowEdgesAsync() {

		CompletableFuture<Circuits> future = lazyCreateCircuitFuture();
		Circuits circuits = getAsync(future); // blocking operation
		if (circuits == null) {
			return Collections.emptySet(); // can happen during dispose
		}
		return Collections.unmodifiableSet(circuits.allCircuits);
	}

	private Set<E> getReverseScopedFlowEdgesForVertexAsync(V v) {
		if (v == null) {
			return null;
		}

		Set<E> flowEdges = reverseScopedFlowEdgeCache.get(v);
		if (flowEdges == null) {
			flowEdges = findReverseScopedFlowAsync(v);
			reverseScopedFlowEdgeCache.put(v, flowEdges);
		}
		return Collections.unmodifiableSet(flowEdges);
	}

	private Set<E> getCircuitEdgesAsync(V v) {

		if (v == null) {
			return null;
		}

		CompletableFuture<Circuits> future = lazyCreateCircuitFuture();
		Circuits circuits = getAsync(future); // blocking operation
		if (circuits == null) {
			return Collections.emptySet(); // can happen during dispose
		}

		Set<E> set = circuits.circuitsByVertex.get(v);
		if (set == null) {
			return Collections.emptySet();
		}
		return Collections.unmodifiableSet(set);
	}

	private <T> T getAsync(CompletableFuture<T> cf) {

		try {
			T t = cf.get(); // blocking
			return t;
		}
		catch (InterruptedException e) {
			Msg.trace(VisualGraphPathHighlighter.this,
				"Unable to calculate graph path highlights - interrupted", e);
		}
		catch (ExecutionException e) {
			Msg.debug(VisualGraphPathHighlighter.this, "Unable to calculate graph path highlights",
				e);
		}
		return null;
	}

	private Circuits calculateCircuitsAsync(TaskMonitor monitor) {

		Circuits result = new Circuits();

		monitor.setMessage("Finding all loops");

		Set<Set<V>> strongs = GraphAlgorithms.getStronglyConnectedComponents(graph);

		for (Set<V> vertices : strongs) {
			if (monitor.isCancelled()) {
				return result;
			}

			if (vertices.size() == 1) {
				continue;
			}

			GDirectedGraph<V, E> subGraph = GraphAlgorithms.createSubGraph(graph, vertices);

			Collection<E> edges = subGraph.getEdges();
			result.allCircuits.addAll(edges);

			HashSet<E> asSet = new HashSet<>(edges);
			Collection<V> subVertices = subGraph.getVertices();
			for (V v : subVertices) {
				if (monitor.isCancelled()) {
					return result;
				}
				result.circuitsByVertex.put(v, asSet);
			}
		}

		result.complete = true;
		return result;
	}

	private List<E> pathToEdgesAsync(List<V> path) {
		List<E> results = new ArrayList<>();

		Iterator<V> it = path.iterator();
		V from = it.next();
		while (it.hasNext()) {
			V to = it.next();
			E e = graph.findEdge(from, to);
			results.add(e);
			from = to;
		}
		return results;
	}

	private Set<E> findForwardScopedFlowAsync(V v) {

		CompletableFuture<ChkDominanceAlgorithm<V, E>> future = lazyCreateDominaceFuture();

		try {

			ChkDominanceAlgorithm<V, E> dominanceAlgorithm = getAsync(future);

			if (dominanceAlgorithm != null) { // null implies timeout
				Set<V> dominated = dominanceAlgorithm.getDominated(v);
				return GraphAlgorithms.retainEdges(graph, dominated);
			}
		}
		catch (Exception e) {
			// handled below
		}

		// use the empty set so we do not repeatedly attempt to calculate these paths
		return Collections.emptySet();
	}

	private Set<E> findReverseScopedFlowAsync(V v) {

		CompletableFuture<ChkDominanceAlgorithm<V, E>> future = lazyCreatePostDominanceFuture();

		try {

			ChkDominanceAlgorithm<V, E> postDominanceAlgorithm = getAsync(future);

			if (postDominanceAlgorithm != null) { // null implies timeout
				Set<V> dominated = postDominanceAlgorithm.getDominated(v);
				return GraphAlgorithms.retainEdges(graph, dominated);
			}
		}
		catch (Exception e) {
			// handled below
		}

		// use the empty set so we do not repeatedly attempt to calculate these paths
		return Collections.emptySet();
	}

	private void calculatePathsBetweenVerticesAsync(V v1, V v2) {

		if (v1.equals(v2)) {
			return;
		}

		CallbackAccumulator<List<V>> accumulator = new CallbackAccumulator<>(path -> {

			Collection<E> edges = pathToEdgesAsync(path);
			SystemUtilities.runSwingLater(() -> setInHoverPathOnSwing(edges));
		});

		TaskMonitor timeoutMonitor = TimeoutTaskMonitor.timeoutIn(ALGORITHM_TIMEOUT,
			TimeUnit.SECONDS, new TaskMonitorAdapter(true));

		try {
			GraphAlgorithms.findPaths(graph, v1, v2, accumulator, timeoutMonitor);
		}
		catch (ConcurrentModificationException e) {
			// TODO temp fix for 8.0.   
			// This exception can happen when the current graph is being mutated off of the 
			// Swing thread, such as when grouping and ungrouping.  For now, squash the 
			// problem, as it is only a UI feature.   Post-"big graph branch merge", update 
			// how we schedule this task in relation to background graph jobs (maybe just make
			// this task a job)
		}
		catch (CancelledException e) {
			SystemUtilities.runSwingLater(
				() -> setStatusTextSwing("Path computation halted by user or timeout.\n" +
					"Paths shown in graph are not complete!"));
		}

	}
//==================================================================================================
// Inner Classes
//==================================================================================================	

	/**
	 * A simple class to hold loops and success status
	 */
	private class Circuits {
		// this is false when the circuit finding takes too long
		private boolean complete;
		private Set<E> allCircuits = new HashSet<>();
		private Map<V, Set<E>> circuitsByVertex = new HashMap<>();

		void clear() {
			allCircuits.clear();
			circuitsByVertex.clear();
		}

		@Override
		public String toString() {
			//@formatter:off
			return "{\n" + 
				"\tall circuits: " + allCircuits + "\n" +
				"\tby vertex: " + circuitsByVertex + "\n" +
			"}";
			//@formatter:on
		}
	}

	/**
	 * A class to handle off-loading the calculation of edges to be hovered.   The results will
	 * then be used to update the UI.
	 */
	private class SetHoveredEdgesRunnable implements SwingRunnable {

		private Supplier<Set<E>> edgeSupplier;
		private Set<E> edges;

		SetHoveredEdgesRunnable(Supplier<Set<E>> edgeSupplier) {
			this.edgeSupplier = edgeSupplier;
		}

		@Override
		public void monitoredRun(TaskMonitor monitor) {
			try {
				edges = edgeSupplier.get();
			}
			catch (CancellationException e) {
				// this can happen as our cache is getting cleared
				monitor.cancel();
			}
		}

		@Override
		public void swingRun(boolean isCancelled) {
			if (isCancelled) {
				return;
			}
			setInHoverPathOnSwing(edges);
		}
	}

	/**
	 * A class to handle off-loading the calculation of edges to be focused.  
	 * The results will then be used to update the UI.
	 */
	private class SetFocusedEdgesRunnable implements SwingRunnable {

		private Supplier<Set<E>> edgeSupplier;
		private Set<E> edges;

		SetFocusedEdgesRunnable(Supplier<Set<E>> edgeSupplier) {
			this.edgeSupplier = edgeSupplier;
		}

		@Override
		public void monitoredRun(TaskMonitor monitor) {
			try {
				edges = edgeSupplier.get();
			}
			catch (CancellationException e) {
				// this can happen as our cache is getting cleared
				monitor.cancel();
			}
		}

		@Override
		public void swingRun(boolean isCancelled) {
			if (isCancelled) {
				return;
			}
			setInFocusedPathOnSwing(edges);
		}
	}

	/**
	 * A class meant to run in the hover RunManager that is slow or open-ended.  Work will
	 * be performed as long as possible, updating results along the way.  
	 */
	private class SlowSetHoveredEdgesRunnable implements MonitoredRunnable {

		private Callback callback;

		SlowSetHoveredEdgesRunnable(Callback callback) {
			this.callback = callback;
		}

		@Override
		public void monitoredRun(TaskMonitor monitor) {
			try {
				callback.call();
			}
			catch (CancellationException e) {
				// this can happen as our cache is getting cleared
				monitor.cancel();
			}
		}
	}
}
