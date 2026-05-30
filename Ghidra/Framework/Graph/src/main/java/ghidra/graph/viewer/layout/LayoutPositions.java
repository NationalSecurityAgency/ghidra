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
package ghidra.graph.viewer.layout;

import java.awt.geom.Point2D;
import java.util.*;
import java.util.Map.Entry;

import edu.uci.ics.jung.algorithms.layout.Layout;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;

/**
 * Simple container class to hold vertex locations (points) and edge articulation locations 
 * (points).  The only complicated code in this class is the use of transformers to create 
 * copies of the given points as they are accessed so that the original points remain unmodified.
 */
public class LayoutPositions<V extends VisualVertex, E extends VisualEdge<V>> {

	private Map<V, Point2D> vertexLocations;
	private Map<E, List<Point2D>> edgeArticulations;

	//@formatter:off
	public static <V extends VisualVertex, E extends VisualEdge<V>> 
		LayoutPositions<V, E> getCurrentPositions(VisualGraph<V, E> graph, Layout<V, E> graphLayout) {
	//@formatter:on

		Map<V, Point2D> locations = new HashMap<>();
		Collection<V> vertices = graph.getVertices();
		for (V vertex : vertices) {
			locations.put(vertex, graphLayout.apply(vertex));
		}

		Map<E, List<Point2D>> articulations = new HashMap<>();
		Collection<E> edges = graph.getEdges();
		for (E edge : edges) {
			articulations.put(edge, edge.getArticulationPoints());
		}

		return new LayoutPositions<>(locations, articulations);
	}

	public static <V extends VisualVertex, E extends VisualEdge<V>> LayoutPositions<V, E> createEmptyPositions() {
		return new LayoutPositions<>();
	}

	public static <V extends VisualVertex, E extends VisualEdge<V>> LayoutPositions<V, E> createNewPositions(
			Map<V, Point2D> vertexLocations, Map<E, List<Point2D>> edgeArticulations) {
		return new LayoutPositions<>(vertexLocations, edgeArticulations);
	}

	private LayoutPositions() {
		// for empty positioning
		vertexLocations = new HashMap<>();
		edgeArticulations = new HashMap<>();
	}

	private LayoutPositions(Map<V, Point2D> vertexLocations,
			Map<E, List<Point2D>> edgeArticulations) {
		setVertexLocations(vertexLocations);
		setEdgeArticulations(edgeArticulations);
	}

	private void setVertexLocations(Map<V, Point2D> newVertexLocations) {

		Map<V, Point2D> newMap = new HashMap<>();
		Set<Entry<V, Point2D>> entries = newVertexLocations.entrySet();
		for (Entry<V, Point2D> entry : entries) {
			V key = entry.getKey();
			Point2D value = entry.getValue();
			newMap.put(key, (Point2D) value.clone());
		}

		this.vertexLocations = newMap;
	}

	private void setEdgeArticulations(Map<E, List<Point2D>> newEdgeArticulations) {

		Map<E, List<Point2D>> newMap = new HashMap<>();
		Set<Entry<E, List<Point2D>>> entries = newEdgeArticulations.entrySet();
		for (Entry<E, List<Point2D>> entry : entries) {
			E key = entry.getKey();
			List<Point2D> value = entry.getValue();
			List<Point2D> newList = new ArrayList<>();
			for (Point2D p : value) {
				newList.add(p);
			}

			newMap.put(key, newList);
		}

		this.edgeArticulations = newMap;
	}

	public Map<V, Point2D> getVertexLocations() {
		// Note: clients are allowed to modify this container!
		return vertexLocations;
	}

	public Map<E, List<Point2D>> getEdgeArticulations() {
		// Note: clients are allowed to modify this container!
		return edgeArticulations;
	}

	public void dispose() {

		//
		// Let's go a bit overboard and help the garbage collector cleanup clearing out our 
		// data structures
		//

		vertexLocations.clear();
		edgeArticulations.clear();
	}

	@Override
	public String toString() {
		return vertexLocations.toString();
	}
}
