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
package ghidra.app.plugin.core.functiongraph.mvc;

import java.awt.Rectangle;
import java.util.Collection;

import javax.swing.JComponent;

import edu.uci.ics.jung.graph.Graph;
import ghidra.app.plugin.core.functiongraph.graph.*;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.layout.LayoutProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.SystemUtilities;
import ghidra.util.task.BusyListener;

public class FGView extends VisualGraphView<FGVertex, FGEdge, FunctionGraph> {

	private FGData functionGraphData = new EmptyFunctionGraphData("Uninitialized Function Graph");

	// Note: this variable is the same 'graphComponent' variable in our parent class.  We need
	//       it store as the more specific type, as it has extra methods we need.
	private FGComponent fgComponent;

	private final FGController controller;

	public FGView(FGController controller, JComponent taskMonitorComponent) {
		this.controller = controller;
		setSouthComponent(taskMonitorComponent);

		setVertexFocusListener(v -> {

			ProgramLocation location = v.getProgramLocation();
			if (location == null) {
				// can happen if the graph data is destroyed, but the graph is still being painted
				return;
			}

			controller.synchronizeProgramLocationToVertex(location);
		});
	}

	void setViewData(FGData data) {
		this.functionGraphData = data;

		if (!data.hasResults()) {
			showErrorView(data.getMessage());
			return;
		}

		setGraph(data.getFunctionGraph());
	}

	@Override
	protected void installGraphViewer() {

		FGComponent newFgComponent = createGraphComponent();
		setGraphComponent(newFgComponent);

		// we must assign the variable here, as the call to setGraphComponent() will call 
		// dispose, which will null-out the 'fgComponent' variable
		fgComponent = newFgComponent;

		// must be done after the 'fgGraphComponent' variable is assigned, due to callbacks
		fgComponent.restoreSettings();
	}

	private FGComponent createGraphComponent() {

		// note: not sure we need the 'busy cursor' here, as the graph has already been 
		//       created at this point
		return getWithBusyCursor(() -> {
			FGComponent newViewer = new FGComponent(this, functionGraphData, layoutProvider);
			return newViewer;
		});
	}

	boolean containsLocation(ProgramLocation newLocation) {
		return functionGraphData.containsLocation(newLocation);
	}

	void setLocation(ProgramLocation location) {
		if (!functionGraphData.containsLocation(location)) {
			return;
		}

		FunctionGraph graph = functionGraphData.getFunctionGraph();
		final FGVertex locationVertex = graph.getVertexForAddress(location.getAddress());
		if (locationVertex == null) {
			return;
		}

		FGVertex focusedVertex = getFocusedVertex();
		ProgramLocation currentLocation = locationVertex.getProgramLocation();
		if (locationVertex == focusedVertex && SystemUtilities.isEqual(currentLocation, location)) {
			ensureCursorOnScreen(locationVertex, false);
			return;
		}

		fgComponent.setVertexFocused(locationVertex, location);

		repaint();

		boolean twinkleVertex = (locationVertex != focusedVertex);
		ensureCursorOnScreen(locationVertex, twinkleVertex);
	}

	private void ensureCursorOnScreen(FGVertex vertex, boolean twinkle) {

		if (fgComponent.isUninitialized()) {
			return;
		}

		BusyListener twinkleAfterAnimationListener = busy -> {
			if (!busy) {
				maybeTwinkleVertex(vertex, twinkle);
			}
		};

		GraphViewer<FGVertex, FGEdge> primaryViewer = getPrimaryGraphViewer();
		Rectangle cursorBounds = vertex.getCursorBounds();
		if (cursorBounds == null) {
			// no cursor yet			
			if (GraphViewerUtils.isScaledPastVertexInteractionThreshold(primaryViewer)) {
				maybeTwinkleVertex(vertex, twinkle);
			}
			return;
		}

		VisualGraphViewUpdater<FGVertex, FGEdge> updater = getViewUpdater();
		updater.ensureVertexAreaVisible(vertex, cursorBounds, twinkleAfterAnimationListener);
	}

	void setSelection(ProgramSelection selection) {
		if (!functionGraphData.containsSelection(selection)) {

			// clear the selection if there is actually data
			if (functionGraphData.hasResults()) {
				FunctionGraph graph = functionGraphData.getFunctionGraph();
				graph.setProgramSelection(new ProgramSelection());
			}
			return;
		}

		FunctionGraph graph = functionGraphData.getFunctionGraph();
		graph.setProgramSelection(selection);

		repaint();
	}

	void setHighlight(ProgramSelection highlight) {
		if (!functionGraphData.containsSelection(highlight)) {
			return;
		}

		FunctionGraph graph = functionGraphData.getFunctionGraph();
		graph.setProgramHighlight(highlight);

		repaint();
	}

	void setViewMode(FGVertex vertex, boolean maximized) {

		if (maximized) {
			setContent(vertex.getMaximizedViewComponent());
		}
		else {
			VisualGraphViewUpdater<FGVertex, FGEdge> updater = getViewUpdater();
			JComponent component = graphComponent.getComponent();
			setContent(component);
			updater.moveVertexToCenterWithoutAnimation(vertex);
		}
	}

	FGVertex getEntryPointVertex() {
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		Function function = functionGraphData.getFunction();
		Address entryPoint = function.getEntryPoint();
		return functionGraph.getVertexForAddress(entryPoint);
	}

	void refreshDisplayWithoutRebuilding() {
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;
		Collection<FGVertex> vertices = graph.getVertices();
		for (FGVertex vertex : vertices) {
			vertex.refreshDisplay();
		}
	}

	void refreshDisplayForAddress(Address address) {
		FunctionGraph graph = functionGraphData.getFunctionGraph();
		FGVertex vertex = graph.getVertexForAddress(address);
		if (vertex == null) {
			return;
		}

		vertex.refreshDisplayForAddress(address);
	}

	void setGraphViewStale(boolean isStale) {
		fgComponent.setGraphViewStale(isStale);
	}

	public boolean isGraphViewStale() {
		if (fgComponent == null) {
			return false;
		}
		return fgComponent.isGraphViewStale();
	}

	/**
	 * Sets the given layout provider, <b>but does not actually perform a layout</b>.
	 */
	@Override
	public void setLayoutProvider(
			LayoutProvider<FGVertex, FGEdge, FunctionGraph> newLayoutProvider) {

		LayoutProvider<FGVertex, FGEdge, FunctionGraph> oldLayoutProvider = layoutProvider;
		super.setLayoutProvider(newLayoutProvider);

		if (graphComponent == null) {
			return; // not yet created, no work to do 
		}

		if (oldLayoutProvider != newLayoutProvider) {
			// the saved positions no longer make sense in a different layout 
			fgComponent.clearLayoutPositionCache();
		}
	}

	// TODO this should move up; remove controller usage
	/**
	 * Performs a relayout of the graph.
	 */
	void relayout() {
		if (fgComponent == null) {
			return; // not yet created, no work to do; layout will happen upon creation
		}

		FGViewUpdater updater = getViewUpdater();
		updater.relayoutGraph(controller);
	}

	@Override
	public FGViewUpdater getViewUpdater() {
		return (FGViewUpdater) super.getViewUpdater();
	}

	/**
	 * Clears user settings, such as vertex locations and group information.
	 */
	void clearUserLayoutSettings() {
		fgComponent.clearAllUserLayoutSettings();
	}

	public void broadcastLayoutRefreshNeeded() {
		controller.rebuildCurrentDisplay();
	}

	public FGController getController() {
		return controller;
	}

	@Override
	protected void disposeViewer() {
		fgComponent = null;
		super.disposeViewer();
	}
}
