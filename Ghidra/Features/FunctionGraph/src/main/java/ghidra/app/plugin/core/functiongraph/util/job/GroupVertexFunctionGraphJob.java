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

import java.awt.geom.Point2D;
import java.util.*;

import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.graph.vertex.GroupedFunctionGraphVertex;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.graph.viewer.layout.LayoutPositions;

public class GroupVertexFunctionGraphJob extends AbstractGroupingFunctionGraphJob {

	private final Point2D groupVertexCurrentLocation;
	private boolean isRegroupOperation = false;
	private FunctionGraph functionGraph;

	public static GroupVertexFunctionGraphJob createNewGroupJob(FGController controller,
			GroupedFunctionGraphVertex groupVertex, Point2D location, boolean relayoutOverride,
			boolean useAnimation) {
		return new GroupVertexFunctionGraphJob(controller, groupVertex, location, relayoutOverride,
			useAnimation, false);
	}

	public static GroupVertexFunctionGraphJob createRegroupJob(FGController controller,
			GroupedFunctionGraphVertex groupVertex, Point2D location, boolean relayoutOverride,
			boolean useAnimation) {
		return new GroupVertexFunctionGraphJob(controller, groupVertex, location, relayoutOverride,
			useAnimation, true);
	}

	public static GroupVertexFunctionGraphJob createUpdateGroupJob(FGController controller,
			GroupedFunctionGraphVertex groupVertex, Set<FGVertex> verticesToGroup,
			boolean useAnimation) {
		return new GroupVertexFunctionGraphJob(controller, groupVertex, verticesToGroup,
			useAnimation);
	}

//==================================================================================================
// Factory Methods
//==================================================================================================	

	/**
	 * Constructor - used when creating a new group
	 * 
	 * @param controller the controller of the graph to be ungrouped
	 * @param groupVertex The group vertex to be ungrouped
	 * @param location The default groupVertex location (only used if not performing a relayout).
	 * @param relayoutOverride a boolean that when true signals to perform a layout <b>
	 * 		  	  			   regardless of the user's relayout options</b>.  This is required to
	 *                         perform a manual relayout.
	 * @param useAnimation whether to use animation
	 * @param isRegroupOperation true if the group is being created as a result of an 
	 *                           operation that restores a previously existing group
	 */
	private GroupVertexFunctionGraphJob(FGController controller,
			GroupedFunctionGraphVertex groupVertex, Point2D location, boolean relayoutOverride,
			boolean useAnimation, boolean isRegroupOperation) {
		super(controller, groupVertex, asSet(groupVertex), groupVertex.getVertices(),
			relayoutOverride, useAnimation);
		this.functionGraph = controller.getFunctionGraphData().getFunctionGraph();
		this.groupVertexCurrentLocation = location;
		this.isRegroupOperation = isRegroupOperation;
	}

	/**
	 * Constructor - used when updating an existing group
	 * 
	 * @param controller the controller of the graph to be ungrouped
	 * @param groupVertex The group vertex to be ungrouped
	 * @param verticesToGroup the vertices to combine into a group
	 * @param useAnimation whether to use animation
	 */
	private GroupVertexFunctionGraphJob(FGController controller,
			GroupedFunctionGraphVertex groupVertex, Set<FGVertex> verticesToGroup,
			boolean useAnimation) {
		super(controller, groupVertex, asSet(groupVertex), verticesToGroup, false, useAnimation);
		this.functionGraph = controller.getFunctionGraphData().getFunctionGraph();
		this.groupVertexCurrentLocation = graphLayout.apply(groupVertex);
	}

//==================================================================================================
// Required Template Methods
//==================================================================================================	

	@Override
	protected void notifyGroupChange() {
		if (isRegroupOperation) {
			functionGraph.groupRestored(groupVertex);
		}
		else {
			functionGraph.groupAdded(groupVertex);
		}
	}

	@Override
	protected Map<FGVertex, Point2D> getGroupingDestinationLocations(boolean isRelayout,
			Point2D groupVertexDestinationLocation) {

		if (groupVertexDestinationLocation == null) {
			groupVertexDestinationLocation = groupVertexCurrentLocation;
		}

		// 'isRelayout' or not, we always want our grouped vertices to end up 
		// at the same locations...
		Map<FGVertex, Point2D> locations = new HashMap<>();

		// put the grouped vertices at the same destination as the group
		for (FGVertex vertex : verticesToBeRemoved) {
			locations.put(vertex, groupVertexDestinationLocation);
		}

		// ...however, the group vertex will either be at the given location, or the layout 
		// location
		if (!isRelayout) {
			// not a relayout--specify the location
			locations.put(groupVertex, groupVertexDestinationLocation);
		}

		return locations;
	}

	@Override
	protected void initializeVertexLocations() {

		//
		// This may be the same as the current locations, or they may be updated, depending upon
		// user options
		// 
		LayoutPositions<FGVertex, FGEdge> positions = updateDestinationLocations();
		Map<FGVertex, Point2D> destinationLocations = positions.getVertexLocations();
		finalEdgeArticulations = positions.getEdgeArticulations();

		//
		// This group of vertices (all those besides the 'verticesToBeRemoved') will be moved
		// to either 1) their new layout positions, or 2) they will stay just where they are.  The
		// 'verticesToBeRemoved' will always be moved somewhere, depending upon the 'relayout' 
		// variable.
		//
		Collection<FGVertex> vertices = getVerticesToMove();
		for (FGVertex vertex : vertices) {
			Point2D currentPoint = graphLayout.apply(vertex);
			Point2D startPoint = (Point2D) currentPoint.clone();
			Point2D destinationPoint = (Point2D) destinationLocations.get(vertex).clone();
			TransitionPoints transitionPoints = new TransitionPoints(startPoint, destinationPoint);
			vertexLocations.put(vertex, transitionPoints);
		}

		//
		// We have to move edge articulations--create transition points.  Depending upon the 
		// value of 'relayout', there may be no edges to update.
		//
		Map<FGEdge, List<Point2D>> edgeArticulations = positions.getEdgeArticulations();
		Collection<FGEdge> edgesToMove = graph.getEdges();
		for (FGEdge edge : edgesToMove) {
			List<Point2D> currentArticulations = edge.getArticulationPoints();
			List<Point2D> newArticulations = edgeArticulations.get(edge);
			if (newArticulations == null) {
				newArticulations = Collections.emptyList();
			}

			List<ArticulationTransitionPoints> transitionPoints = getArticulationTransitionPoints(
				currentArticulations, newArticulations, destinationLocations, edge);

			edgeArticulationLocations.put(edge, transitionPoints);
		}

	}

	private List<ArticulationTransitionPoints> getArticulationTransitionPoints(
			List<Point2D> currentArticulations, List<Point2D> newArticulations,
			Map<FGVertex, Point2D> destinationLocations, FGEdge edge) {

		if (currentArticulations.size() > newArticulations.size()) {
			return getArticulationTransitionPointsWhenStartingWithMorePoints(currentArticulations,
				newArticulations, destinationLocations, edge);
		}
		return getArticulationTransitionPointsWhenStartingWithLessPoints(currentArticulations,
			newArticulations, destinationLocations, edge);
	}

	private List<ArticulationTransitionPoints> getArticulationTransitionPointsWhenStartingWithMorePoints(
			List<Point2D> currentArticulations, List<Point2D> newArticulations,
			Map<FGVertex, Point2D> destinationLocations, FGEdge edge) {
		List<ArticulationTransitionPoints> transitionPoints = new ArrayList<>();

		for (int i = 0; i < currentArticulations.size(); i++) {
			Point2D startPoint = currentArticulations.get(i);
			Point2D endPoint = (Point2D) startPoint.clone();
			if (i < newArticulations.size()) {
				// prefer the new articulations, while we have some
				endPoint = newArticulations.get(i);
			}
			else {
				// less articulations in the new layout--map to the destination point of the
				// destination vertex
				FGVertex destinationVertex = edge.getEnd();
				TransitionPoints destionationTranstionPoint =
					getTransitionPoint(vertexLocations, destinationLocations, destinationVertex);
				endPoint = destionationTranstionPoint.destinationPoint;
			}

			transitionPoints.add(new ArticulationTransitionPoints(startPoint, endPoint));
		}

		return transitionPoints;
	}

	private List<ArticulationTransitionPoints> getArticulationTransitionPointsWhenStartingWithLessPoints(
			List<Point2D> currentArticulations, List<Point2D> newArticulations,
			Map<FGVertex, Point2D> destinationLocations, FGEdge edge) {

		List<ArticulationTransitionPoints> transitionPoints = new ArrayList<>();

		// 
		// In this case we will have to add articulations to the current edge now so that we can
		// animate their creation.
		//
		List<Point2D> newStartArticulationsPoints = new ArrayList<>();

		// default to start vertex so to handle the case where we started with no articulations
		Point2D lastValidStartPoint = graphLayout.apply(edge.getStart());
		for (int i = 0; i < newArticulations.size(); i++) {
			Point2D endPoint = newArticulations.get(i);
			Point2D startPoint = (Point2D) lastValidStartPoint.clone();
			if (i < currentArticulations.size()) {
				// prefer the new articulations, while we have some
				startPoint = currentArticulations.get(i);
				lastValidStartPoint = startPoint;
			}

			transitionPoints.add(new ArticulationTransitionPoints(startPoint, endPoint));
			newStartArticulationsPoints.add(startPoint);
		}

		edge.setArticulationPoints(newStartArticulationsPoints);
		return transitionPoints;
	}

	private TransitionPoints getTransitionPoint(Map<FGVertex, TransitionPoints> transitionPoints,
			Map<FGVertex, Point2D> destinationLocations, FGVertex vertex) {
		TransitionPoints transtionPoint = transitionPoints.get(vertex);
		if (transtionPoint != null) {
			return transtionPoint;
		}

		// We have a destination vertex that is not being moved, so it is not
		// in the 'transitionPoints'.  Create a TransitionPoint for it.
		return createTransitionPoint(destinationLocations, vertex);
	}

	private TransitionPoints createTransitionPoint(Map<FGVertex, Point2D> destinationLocations,
			FGVertex vertex) {
		Point2D currentPoint = graphLayout.apply(vertex);
		Point2D startPoint = (Point2D) currentPoint.clone();
		Point2D destinationPoint = (Point2D) destinationLocations.get(vertex).clone();
		return new TransitionPoints(startPoint, destinationPoint);
	}
}
