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

import static ghidra.graph.viewer.GraphViewerUtils.*;

import java.awt.*;
import java.awt.geom.PathIterator;
import java.awt.geom.Point2D;
import java.util.*;
import java.util.List;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.commons.collections4.*;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.graph.util.Pair;
import edu.uci.ics.jung.visualization.VisualizationServer;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import ghidra.graph.viewer.renderer.DebugShape;

class ArticulatedEdgeRouter<V extends VisualVertex, E extends VisualEdge<V>>
		extends BasicEdgeRouter<V, E> {

	private Shape spaceBetweenEndPointsShape;  // layout space
	private Map<V, Rectangle> cachedVertexBoundsMap;

	private static final AtomicInteger debugCounter = new AtomicInteger(1);

	ArticulatedEdgeRouter(VisualizationServer<V, E> viewer, Collection<E> edges) {
		super(viewer, edges);
		this.viewer = viewer;
		this.edges = edges;
	}

	@Override
	public void route() {
		debugCounter.set(debugCounter.incrementAndGet());

		Layout<V, E> layout = viewer.getGraphLayout();
		Graph<V, E> graph = layout.getGraph();

		for (E edge : edges) {

			Shape edgeShape = getEdgeShapeInGraphSpace(viewer, edge);
			if (!isOccluded(edge, edgeShape)) {
				DebugShape<V, E> debugShape = new DebugShape<>(viewer, debugCounter, "Default",
					getEdgeShapeInGraphSpace(viewer, edge), getPhantomEdgeColor(edge, true));
				viewer.addPostRenderPaintable(debugShape);
				List<Point2D> articulations = edge.getArticulationPoints();
				if (!articulations.isEmpty()) {
					articulations = removeBadlyAngledArticulations(edge, articulations);
					edge.setArticulationPoints(articulations);
					continue;
				}
			}

			Pair<V> endpoints = graph.getEndpoints(edge);
			V start = endpoints.getFirst();
			V end = endpoints.getSecond();

			if (start == end) {
				continue; // self-loop
			}

			Point2D startPoint = layout.apply(start);
			Point2D endPoint = layout.apply(end);

			Shape boxBetweenVertices = createRectangle(startPoint, endPoint);
			Shape xBox = translateShapeFromLayoutSpaceToGraphSpace(boxBetweenVertices, viewer);
			spaceBetweenEndPointsShape = constrictToVerticesInsideShape(xBox, start, end);

			DebugShape<V, E> debugShape = new DebugShape<>(viewer, debugCounter, "Restricted Box",
				translateShapeFromLayoutSpaceToGraphSpace(spaceBetweenEndPointsShape, viewer),
				getRoutingBoxColor(edge));
			viewer.addPostRenderPaintable(debugShape);

//			Shape line = createLineEdge(viewer, start, end, edge);
//			if (!isOccluded(viewer, edge, line)) {
//				edge.setLayoutArticulationPoints(new ArrayList<Point2D>());
//				continue;
//			}

			Shape routedShape = createRoutedTwoPointShape(start, end, edge, true);
			debugShape = new DebugShape<>(viewer, debugCounter, "Left Edge", routedShape,
				getPhantomEdgeColor(edge, true));
			viewer.addPostRenderPaintable(debugShape);
			List<Point2D> articulations = getArticulations(routedShape);
			if (!isOccluded(edge, routedShape)) {
				articulations = removeBadlyAngledArticulations(edge, articulations);
				edge.setArticulationPoints(articulations);
				continue;
			}

// TODO: add a loop here to try moving the articulations out a bit			

			routedShape = createRoutedTwoPointShape(start, end, edge, false);
			debugShape = new DebugShape<>(viewer, debugCounter, "Right edge", routedShape,
				getPhantomEdgeColor(edge, false));
			viewer.addPostRenderPaintable(debugShape);
			articulations = getArticulations(routedShape);

			if (!isOccluded(edge, routedShape)) {

				articulations = removeBadlyAngledArticulations(edge, articulations);
				edge.setArticulationPoints(articulations);
				continue;
			}

			// do the basic--just a default edge line
			edge.setArticulationPoints(new ArrayList<Point2D>());
		}
	}

	private Shape constrictToVerticesInsideShape(Shape boundingShape, V start, V end) {
		Set<V> vertices = new HashSet<>();

		Map<V, Rectangle> vertexBoundsMap = getVertexBounds();
		Set<Entry<V, Rectangle>> entrySet = vertexBoundsMap.entrySet();
		for (Entry<V, Rectangle> entry : entrySet) {
			V v = entry.getKey();
			Rectangle vertexBounds = getVertexBoundsInGraphSpace(viewer, v);
			if (boundingShape.intersects(vertexBounds)) {
				vertices.add(v);
			}
		}

		vertices.remove(start); // don't include the edges vertices in the shape
		vertices.remove(end);

		if (vertices.isEmpty()) {
			boundingShape.getBounds().setSize(0, 0);
			return boundingShape;
		}

		return getBoundsForVerticesInLayoutSpace(viewer, vertices);
	}

	private Rectangle createRectangle(Point2D startPoint, Point2D endPoint) {

		double smallestX = Math.min(startPoint.getX(), endPoint.getX());
		double smallestY = Math.min(startPoint.getY(), endPoint.getY());
		double largestX = Math.max(startPoint.getX(), endPoint.getX());
		double largestY = Math.max(startPoint.getY(), endPoint.getY());
		int width = (int) (largestX - smallestX);
		int height = (int) (largestY - smallestY);
		return new Rectangle((int) smallestX, (int) smallestY, width, height);
	}

	private void moveArticulationsAroundVertices(Set<V> vertices, E edge, boolean goLeft) {

		Layout<V, E> layout = viewer.getGraphLayout();
		Graph<V, E> graph = layout.getGraph();
		Pair<V> endpoints = graph.getEndpoints(edge);

		V start = endpoints.getFirst();
		V end = endpoints.getSecond();
		Point2D startPoint = layout.apply(start);
		Point2D endPoint = layout.apply(end);

//		Rectangle bounds = getBoundsForVerticesInLayoutSpace(viewer, vertices);

// paint the shape
//		Color color = getIntersectingBoxColor(edge);
//		String name = goLeft ? "Left" : "Right";
//		DebugShape<V, E> debugShape =
//			new DebugShape<V, E>(viewer, debugCounter, name,
//				translateShapeFromLayoutSpaceToGraphSpace(bounds, viewer), color);
//		viewer.addPostRenderPaintable(debugShape);

		Rectangle bounds = spaceBetweenEndPointsShape.getBounds();

		int padding = 20;
		int x = goLeft ? bounds.x : bounds.x + bounds.width;
		x += goLeft ? -padding : padding;

		Point2D top = new Point2D.Double(x, bounds.y - padding);
		Point2D bottom = new Point2D.Double(x, bounds.y + bounds.height + padding);

		if (startPoint.getY() > endPoint.getY()) {
			// swap the top and bottom points, as our source vertex is below the destination
			Point2D newTop = bottom;
			bottom = top;
			top = newTop;
		}

		List<Point2D> articulationPoints = new ArrayList<>();
		articulationPoints.add(top);
		articulationPoints.add(bottom);

		edge.setArticulationPoints(articulationPoints);
	}

	// the edge is cloned from the given edge--safe
	private Shape createRoutedTwoPointShape(V start, V end, E edge, boolean goLeft) {

		Set<E> edgesSet = new HashSet<>();
		edgesSet.add(edge);
		Map<E, Set<V>> occludedEdges = getOccludedEdges(edgesSet);
		Set<V> intersectingVertices = occludedEdges.get(edge);

		if (intersectingVertices.isEmpty()) {
			// not sure what to do yet, just draw a straight line
			return createLineEdge(start, end, edge);
		}

		E newEdge = (E) edge.cloneEdge(edge.getStart(), edge.getEnd());
		moveArticulationsAroundVertices(intersectingVertices, newEdge, goLeft);

		return getEdgeShapeInGraphSpace(viewer, newEdge);
	}

	/**
	 * Returns a mapping edges to vertices that touch them.
	 * 
	 * @param viewer the viewer containing the graph
	 * @param edgeCollection the edges to check for occlusion
	 * @return a mapping of occluded edges (a subset of the provided edges) to those vertices that
	 *         occlude them.
	 */
	private Map<E, Set<V>> getOccludedEdges(Collection<E> edgeCollection) {

		Layout<V, E> layout = viewer.getGraphLayout();
		Graph<V, E> graph = layout.getGraph();

		Set<V> prototype = new HashSet<>();
		Factory<Set<V>> factory = FactoryUtils.prototypeFactory(prototype);
		Map<E, Set<V>> map = MapUtils.lazyMap(new HashMap<E, Set<V>>(), factory);

		Map<V, Rectangle> vertexBoundsMap = getVertexBounds();
		Set<Entry<V, Rectangle>> entrySet = vertexBoundsMap.entrySet();
		for (Entry<V, Rectangle> entry : entrySet) {
			V v = entry.getKey();
			Rectangle vertexBounds = getVertexBoundsInGraphSpace(viewer, v);

			for (E edge : edgeCollection) {
				Shape edgeShape = getEdgeShapeInGraphSpace(viewer, edge);
				Pair<V> endpoints = graph.getEndpoints(edge);
				if (v == endpoints.getFirst() || v == endpoints.getSecond()) {
					// do we ever care if an edge is occluded by its own vertices?
					continue;
				}

				if (edgeShape.intersects(vertexBounds)) {
					Set<V> set = map.get(edge);
					set.add(v);
				}
			}
		}

		return map;
	}

	private Map<V, Rectangle> getVertexBounds() {
		if (cachedVertexBoundsMap != null) {
			return cachedVertexBoundsMap;
		}

		Layout<V, E> layout = viewer.getGraphLayout();
		Graph<V, E> graph = layout.getGraph();
		Collection<V> vertices = graph.getVertices();

		Map<V, Rectangle> map = new HashMap<>();
		for (V v : vertices) {
			Rectangle vertexBounds = getVertexBoundsInGraphSpace(viewer, v);
			map.put(v, vertexBounds);
		}

		cachedVertexBoundsMap = map;
		return map;
	}

	private List<Point2D> getArticulations(Shape shape) {
		PathIterator pathIterator = shape.getPathIterator(null);
		List<Point2D> articulations = new ArrayList<>();
		double[] coords = new double[6];

		// Note: this extraction is based upon a two articulation edge!
		pathIterator.next(); // skip the first value, the start vertex value

		// 2nd element is the first articulation
		pathIterator.currentSegment(coords);
		Point2D.Double pathPoint = new Point2D.Double(coords[0], coords[1]);
		Point layoutSpacePoint = translatePointFromGraphSpaceToLayoutSpace(pathPoint, viewer);
		articulations.add(layoutSpacePoint);

		// 3rd element is the second articulation
		pathIterator.next();
		pathIterator.currentSegment(coords);
		pathPoint = new Point2D.Double(coords[0], coords[1]);
		layoutSpacePoint = translatePointFromGraphSpaceToLayoutSpace(pathPoint, viewer);
		articulations.add(layoutSpacePoint);

		return articulations;
	}

	private Shape createLineEdge(V start, V end, E edge) {

		edge.setArticulationPoints(new ArrayList<Point2D>()); // clear the points--straight line

		return getEdgeShapeInGraphSpace(viewer, edge);
	}

	private Color getRoutingBoxColor(E edge) {
		if (isTrueEdge(edge)) {
			return Color.MAGENTA;
		}
		return Color.ORANGE;
	}

//
//	private Color getIntersectingBoxColor(E edge) {
//		if (isTrueEdge(edge)) {
//			return Color.RED;
//		}
//		return Color.PINK;
//	}

	private Color getPhantomEdgeColor(E edge, boolean isLeft) {
		if (isLeft) {
			if (isTrueEdge(edge)) {
				return new Color(0x999900);
			}

			return new Color(0x009900);
		}
		if (isTrueEdge(edge)) {
			return new Color(0x3300CC);
		}
		return new Color(0x3399FF);
	}

	private boolean isTrueEdge(E edge) {
		return true;
		// return edge.getFlowType().isJump(); // a jump is a 'true' edge
	}
}
