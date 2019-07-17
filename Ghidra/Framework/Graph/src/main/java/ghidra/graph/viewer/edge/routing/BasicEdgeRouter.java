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
package ghidra.graph.viewer.edge.routing;

import static ghidra.graph.viewer.GraphViewerUtils.getVertexBoundsInGraphSpace;

import java.awt.Rectangle;
import java.awt.Shape;
import java.awt.geom.Point2D;
import java.util.*;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.graph.util.Pair;
import edu.uci.ics.jung.visualization.VisualizationServer;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;

public class BasicEdgeRouter<V extends VisualVertex, E extends VisualEdge<V>> {

	protected VisualizationServer<V, E> viewer;
	protected Collection<E> edges = null;

	public BasicEdgeRouter(VisualizationServer<V, E> viewer, Collection<E> edges) {
		this.viewer = viewer;
		this.edges = edges;
	}

	public void route() {
		for (E edge : edges) {
			List<Point2D> articulations = edge.getArticulationPoints();

			if (articulations.isEmpty()) {
				continue; // nothing to do
			}

			articulations = removeBadlyAngledArticulations(edge, articulations);
			edge.setArticulationPoints(articulations);

// TODO: not sure if we want to test for occlusion here too			
//			Shape edgeShape = getEdgeShapeInGraphSpace(viewer, edge);
//			if (!isOccluded(edge, edgeShape)) {
//
//			}
		}
	}

	protected boolean isOccluded(E edge, Shape graphSpaceShape) {

		Layout<V, E> layout = viewer.getGraphLayout();
		Graph<V, E> graph = layout.getGraph();
		Collection<V> vertices = graph.getVertices();

		for (V vertex : vertices) {
			Rectangle vertexBounds = getVertexBoundsInGraphSpace(viewer, vertex);

			Pair<V> endpoints = graph.getEndpoints(edge);
			if (vertex == endpoints.getFirst() || vertex == endpoints.getSecond()) {
				// do we ever care if an edge is occluded by its own vertices?
				continue;
			}

			if (graphSpaceShape.intersects(vertexBounds)) {
				return true;
			}
		}

		return false;
	}

	protected List<Point2D> removeBadlyAngledArticulations(E edge, List<Point2D> articulations) {

		Layout<V, E> layout = viewer.getGraphLayout();
		Graph<V, E> graph = layout.getGraph();
		Pair<V> endpoints = graph.getEndpoints(edge);
		V start = endpoints.getFirst();
		V end = endpoints.getSecond();

		Point2D startPoint = layout.apply(start);
		Point2D endPoint = layout.apply(end);

		if (startPoint.getY() > endPoint.getY()) {
			// swap the top and bottom points, as our source vertex is below the destination
			Point2D newStart = endPoint;
			endPoint = startPoint;
			startPoint = newStart;
		}

		List<Point2D> newList = new ArrayList<>();
		for (Point2D articulation : articulations) {
			double deltaY = articulation.getY() - startPoint.getY();
			double deltaX = articulation.getX() - startPoint.getX();
			double theta = Math.atan2(deltaY, deltaX);
			double degrees = theta * 180 / Math.PI;

			if (degrees < 0 || degrees > 180) {
				continue;
			}

			deltaY = endPoint.getY() - articulation.getY();
			deltaX = endPoint.getX() - articulation.getX();
			theta = Math.atan2(deltaY, deltaX);
			degrees = theta * 180 / Math.PI;

			if (degrees < 0 || degrees > 180) {
				continue;
			}

			newList.add(articulation);
		}

		return newList;
	}
}
