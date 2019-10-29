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
package ghidra.app.plugin.core.functiongraph.util.job;

import java.awt.Rectangle;
import java.awt.geom.Point2D;
import java.util.*;

import org.apache.commons.collections4.IterableUtils;
import org.jdesktop.animation.timing.Animator;
import org.jdesktop.animation.timing.interpolation.PropertySetter;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.visualization.VisualizationServer;
import edu.uci.ics.jung.visualization.util.Caching;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.app.plugin.core.functiongraph.mvc.FGData;
import ghidra.graph.job.AbstractAnimatorJob;

public class MergeVertexFunctionGraphJob extends AbstractAnimatorJob {

	private static final int DURATION = 1500;

	private final VisualizationServer<FGVertex, FGEdge> viewer;
	private Layout<FGVertex, FGEdge> graphLayout;
	private final FGVertex mergedVertex;
	private final FGVertex parentVertex;
	private final FGVertex childVertex;

	private Point2D parentStart;
	private Point2D childStart;
	private Point2D parentDestination;
	private Point2D childDestination;
	private Point2D mergedDestination;

	private final boolean useAnimation;

	private final FGController controller;

	public MergeVertexFunctionGraphJob(FGController controller,
			VisualizationServer<FGVertex, FGEdge> viewer, final FGVertex mergedVertex,
			FGVertex newParentVertex, FGVertex newChildVertex, boolean useAnimation) {
		this.controller = controller;
		this.viewer = viewer;
		this.mergedVertex = mergedVertex;
		this.parentVertex = newParentVertex;
		this.childVertex = newChildVertex;
		this.useAnimation = useAnimation;
		this.graphLayout = viewer.getGraphLayout();

		updateOpacity(0D); // don't paint this vertex or its edges initially
	}

	@Override
	public boolean canShortcut() {
		return false;
	}

	@Override
	public void shortcut() {
		throw new UnsupportedOperationException("Cannot cancel this job: " + this);
	}

	@Override
	protected Animator createAnimator() {
		initializeVertexLocations();

		if (!useAnimation) {
			return null;
		}

		Animator newAnimator =
			PropertySetter.createAnimator(DURATION, this, "percentComplete", 0.0, 1.0);
		newAnimator.setAcceleration(0f);
		newAnimator.setDeceleration(0.8f);
		return newAnimator;
	}

	@Override
	protected void finished() {
		if (isShortcut) {
			initializeVertexLocations();
		}

		clearLocationCache();
		graphLayout.setLocation(mergedVertex, mergedDestination);
		removeOldVertexAndEdges();

		updateOpacity(1D);

		controller.synchronizeProgramLocationAfterEdit();

		viewer.repaint();
	}

	public void setPercentComplete(double percentComplete) {
		updateNewVertexPositions(percentComplete);
		updateOpacity(percentComplete);
		viewer.repaint();
	}

	protected void clearLocationCache() {
		Layout<FGVertex, FGEdge> jungLayout = viewer.getGraphLayout();
		((Caching) jungLayout).clear();
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void initializeVertexLocations() {
		// 
		// We will create the new locations for the new parent and child vertices.  There will
		// be the initial (start) location for each one and the destination location for each
		// one.  This allows us to show a transition from the start to the destination point.
		//		

		// Update the new parent node to compensate for its new size.  This code effectively 
		// moves the new vertex up to account for the fact that its overall height has been 
		// reduced.  This is necessary to prevent the vertex from moving down, as the location of
		// a vertex is based upon its center point.
		Rectangle originalBounds = parentVertex.getBounds();
		Rectangle newBounds = mergedVertex.getBounds();
		int dy = (newBounds.height - originalBounds.height) >> 1;

		Point2D parentLocation = graphLayout.apply(parentVertex);
		Point2D mergedLocation = (Point2D) parentLocation.clone();
		mergedLocation.setLocation(parentLocation.getX(), parentLocation.getY() + dy);

		parentStart = parentLocation;
		parentDestination = parentStart; // this vertex doesn't move
		childStart = graphLayout.apply(childVertex);
		childDestination = parentDestination; // they will end up together
		mergedDestination = mergedLocation;

		Point2D oldLocationProperty = parentVertex.getLocation();
		mergedVertex.setLocation(oldLocationProperty);
		graphLayout.setLocation(mergedVertex, mergedDestination); // tell the graph the new location

		// note: due to the caching nature of some layouts, if we don't reset this, then 
		// some of our GUI calculations will be incorrect (like when we try to fit the 
		// satellite in it's window).  So, we always have to clear the cache when we set locations
		clearLocationCache();
	}

	private void updateNewVertexPositions(double percentComplete) {
		//
		// The new position is some percentage of the distance between the start 
		// position and the destination position
		//
		double parentDestinationX = parentDestination.getX();
		double parentDeltaX = (parentDestinationX - parentStart.getX()) * percentComplete;
		double childDestinationY = childDestination.getY();
		double childDeltaY = (childDestinationY - childStart.getY()) * percentComplete;

		double childDestinationX = childDestination.getX();
		double childDeltaX = (childDestinationX - childStart.getX()) * percentComplete;
		double parentDestinationY = parentDestination.getY();
		double parentDeltaY = (parentDestinationY - parentStart.getY()) * percentComplete;

		double newParentX = parentStart.getX() + parentDeltaX;
		double newParentY = parentStart.getY() + parentDeltaY;

		double newChildX = childStart.getX() + childDeltaX;
		double newChildY = childStart.getY() + childDeltaY;

		Point2D newParentLocation = new Point2D.Double(newParentX, newParentY);
		Point2D newChildLocation = new Point2D.Double(newChildX, newChildY);

		// this is needed for the edges to paint correctly, as they may be articulated
		parentVertex.setLocation(newParentLocation);
		childVertex.setLocation(newChildLocation);

		clearLocationCache(); // the new values won't be read if we don't clear the cache
		graphLayout.setLocation(parentVertex, newParentLocation);
		graphLayout.setLocation(childVertex, newChildLocation);
	}

	private void updateOpacity(double percentComplete) {
		double oldComponentsAlpha = 1.0 - percentComplete;
		parentVertex.setAlpha(oldComponentsAlpha);
		childVertex.setAlpha(oldComponentsAlpha);

		Iterable<FGEdge> edges =
			IterableUtils.chainedIterable(getEdges(parentVertex), getEdges(childVertex));
		for (FGEdge edge : edges) {

			// don't go past the alpha when removing
			double defaultAlpha = edge.getDefaultAlpha();
			double alpha = Math.min(oldComponentsAlpha, defaultAlpha);
			edge.setAlpha(alpha);
		}

		double newComponentsAlpha = percentComplete;
		mergedVertex.setAlpha(newComponentsAlpha);
		edges = getEdges(mergedVertex);
		for (FGEdge edge : edges) {

			// don't go past the alpha when adding
			double defaultAlpha = edge.getDefaultAlpha();
			double alpha = Math.min(newComponentsAlpha, defaultAlpha);
			edge.setAlpha(alpha);
		}
	}

	private Collection<FGEdge> getEdges(FGVertex vertex) {
		Graph<FGVertex, FGEdge> graph = graphLayout.getGraph();
		List<FGEdge> edges = new LinkedList<>();
		Collection<FGEdge> inEdges = graph.getInEdges(vertex);
		if (inEdges != null) {
			edges.addAll(inEdges);
		}

		Collection<FGEdge> outEdges = graph.getOutEdges(vertex);
		if (outEdges != null) {
			edges.addAll(outEdges);
		}

		return edges;
	}

	private void removeOldVertexAndEdges() {
		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph graph = functionGraphData.getFunctionGraph();
		graph.removeVertex(parentVertex);
		graph.removeVertex(childVertex);
	}
}
