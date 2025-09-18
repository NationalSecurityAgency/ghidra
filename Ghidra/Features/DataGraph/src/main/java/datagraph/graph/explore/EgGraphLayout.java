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
package datagraph.graph.explore;

import java.awt.Rectangle;
import java.awt.Shape;
import java.awt.geom.Point2D;
import java.util.*;
import java.util.function.Function;

import javax.help.UnsupportedOperationException;

import edu.uci.ics.jung.visualization.RenderContext;
import edu.uci.ics.jung.visualization.renderers.BasicEdgeRenderer;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.layout.*;
import ghidra.graph.viewer.layout.LayoutListener.ChangeType;
import ghidra.graph.viewer.vertex.VisualGraphVertexShapeTransformer;
import ghidra.util.task.TaskMonitor;

/**
 * A custom layout to arrange the vertices of an {@link AbstractExplorationGraph} using a tree
 * structure that reflects the exploration order of the vertices. The basic algorithm is that 
 * an original vertex is the root vertex and all other vertices are displayed in a double tree
 * structure that show a tree of outgoing edges to the right and a tree of incoming edges
 * to the left.  The immediate vertices at each level are simply shown in a vertical column. 
 * <P>
 * However, the tricky concept is that each vertex can then have edges that go back. For example,
 * if the original vertex has three outgoing vertices, but then those 
 * vertices can spawn other incoming vertices. In this case, the vertex is pushed further out to
 * make room for its spawned incoming vertices. This is done recursively, where each child 
 * vertex's sub tree is computed and then all the child subtrees are stacked in a column.
 * 
 * @param <V> the vertex type 
 * @param <E> the edge type
 */
public abstract class EgGraphLayout<V extends EgVertex, E extends EgEdge<V>>
		extends AbstractVisualGraphLayout<V, E> {

	private EgEdgeRenderer<V, E> edgeRenderer = new EgEdgeRenderer<>();
	private EgEdgeTransformer<V, E> edgeTransformer;
	private Function<V, Shape> vertexShapeTransformer = new VisualGraphVertexShapeTransformer<V>();
	protected int verticalGap;
	protected int horizontalGap;

	protected EgGraphLayout(AbstractExplorationGraph<V, E> graph, String name, int verticalGap,
			int horizontalGap) {
		super(graph, name);
		this.verticalGap = verticalGap;
		this.horizontalGap = horizontalGap;
		this.edgeTransformer = createEdgeTransformer();
	}

	protected abstract EgEdgeTransformer<V, E> createEdgeTransformer();

	protected abstract Comparator<V> getIncommingVertexComparator();

	protected abstract Comparator<V> getOutgoingVertexComparator();

	@Override
	public Point2D apply(V v) {
		if (v.hasUserChangedLocation()) {
			return v.getLocation();
		}
		return super.apply(v);
	}

	@SuppressWarnings("unchecked")
	@Override
	public VisualGraph<V, E> getVisualGraph() {
		return (VisualGraph<V, E>) getGraph();
	}

	@Override
	public BasicEdgeRenderer<V, E> getEdgeRenderer() {
		return edgeRenderer;
	}

	@Override
	public com.google.common.base.Function<E, Shape> getEdgeShapeTransformer(
			RenderContext<V, E> context) {

		return edgeTransformer;
	}

	@Override
	protected LayoutPositions<V, E> doCalculateLocations(VisualGraph<V, E> g,
			TaskMonitor taskMonitor) {
		if (!(g instanceof AbstractExplorationGraph<V, E> layeredGraph)) {
			throw new IllegalArgumentException("This layout only supports Layered graphs!");
		}

		try {
			monitor = taskMonitor;
			return computePositions(layeredGraph);
		}
		finally {
			monitor = TaskMonitor.DUMMY;
		}

	}

	private LayoutPositions<V, E> computePositions(AbstractExplorationGraph<V, E> g) {
		GraphLocationMap<V> locationMap = getLocationMap(g, g.getRoot());
		Map<V, Point2D> vertexLocations = locationMap.getVertexLocations();
		return LayoutPositions.createNewPositions(vertexLocations,
			Collections.emptyMap());

	}

	@Override
	protected GridLocationMap<V, E> performInitialGridLayout(VisualGraph<V, E> g) {
		// we override the method that calls this abstract method, so it isn't used.
		throw new UnsupportedOperationException();
	}

	private GraphLocationMap<V> getLocationMap(AbstractExplorationGraph<V, E> g, V v) {
		List<GraphLocationMap<V>> leftMaps = getMapsForIncommingEdges(g, v);
		List<GraphLocationMap<V>> rightMaps = getMapsForOutgoingEdges(g, v);

		Shape shape = vertexShapeTransformer.apply(v);
		Rectangle bounds = shape.getBounds();
		GraphLocationMap<V> baseMap = new GraphLocationMap<>(v, bounds.width, bounds.height);

		if (leftMaps != null) {
			mergeLeftMaps(baseMap, leftMaps);
		}
		if (rightMaps != null) {
			mergeRightMaps(baseMap, rightMaps);
		}
		return baseMap;
	}

	/**
	 * Merges all the incoming vertex sub-tree maps in a column to the left of the base map. Since
	 * these maps will all be to the left of their parent vertex base map, we align them in the
	 * column such that their right map edge boundaries align.
	 * @param baseMap the map for the parent vertex
	 * @param leftMaps the list of maps to be organized in a column to the left of the base map.
	 */
	private void mergeLeftMaps(GraphLocationMap<V> baseMap, List<GraphLocationMap<V>> leftMaps) {

		int shiftY = getTopGroupShift(leftMaps, verticalGap);
		int baseShiftX = baseMap.getMinX() - horizontalGap;
		for (GraphLocationMap<V> map : leftMaps) {
			shiftY += map.getHeight() / 2;
			int shiftX = baseShiftX - map.getMaxX();
			baseMap.merge(map, shiftX, shiftY);
			shiftY += map.getHeight() / 2 + verticalGap;
		}
	}

	/**
	 * Merges all the outgoing vertex sub-tree maps in a column to the right of the base map. Since
	 * these maps will all be to the right of their parent vertex base map, we align them in the
	 * column such that their left map edge boundaries align.
	 * @param baseMap the map for the parent vertex
	 * @param rightMaps the list of maps to be organized in a column to the right of the base map.
	 */
	private void mergeRightMaps(GraphLocationMap<V> baseMap, List<GraphLocationMap<V>> rightMaps) {
		int shiftY = getTopGroupShift(rightMaps, verticalGap);
		int baseShiftX = baseMap.getMaxX() + horizontalGap;
		for (GraphLocationMap<V> map : rightMaps) {
			shiftY += map.getHeight() / 2;
			int shiftX = baseShiftX - map.getMinX();
			baseMap.merge(map, shiftX, shiftY);
			shiftY += map.getHeight() / 2 + verticalGap;
		}
	}

	private int getTopGroupShift(List<GraphLocationMap<V>> maps, int gap) {
		int totalHeight = 0;
		for (GraphLocationMap<V> map : maps) {
			totalHeight += map.getHeight();
		}
		totalHeight += (maps.size() - 1) * gap;
		return -totalHeight / 2;
	}

	private List<GraphLocationMap<V>> getMapsForOutgoingEdges(AbstractExplorationGraph<V, E> g,
			V v) {
		List<E> edges = getOutgoingNextLayerEdges(g, v);
		if (edges == null || edges.isEmpty()) {
			return null;
		}
		return getOutgoingGraphMaps(g, edges);
	}

	private List<GraphLocationMap<V>> getMapsForIncommingEdges(AbstractExplorationGraph<V, E> g,
			V v) {
		List<E> edges = getIncommingNextLayerEdges(g, v);
		if (edges == null || edges.isEmpty()) {
			return null;
		}
		return getIncomingGraphMaps(g, edges);
	}

	private List<GraphLocationMap<V>> getOutgoingGraphMaps(AbstractExplorationGraph<V, E> g,
			List<E> edges) {
		List<GraphLocationMap<V>> maps = new ArrayList<>(edges.size());
		for (E e : edges) {
			maps.add(getLocationMap(g, e.getEnd()));
		}
		return maps;
	}

	private List<GraphLocationMap<V>> getIncomingGraphMaps(AbstractExplorationGraph<V, E> g,
			List<E> edges) {
		List<GraphLocationMap<V>> maps = new ArrayList<>(edges.size());
		for (E e : edges) {
			maps.add(getLocationMap(g, e.getStart()));
		}
		return maps;
	}

	private List<E> getOutgoingNextLayerEdges(AbstractExplorationGraph<V, E> g, V v) {
		Collection<E> outEdges = g.getOutEdges(v);
		if (outEdges == null || outEdges.isEmpty()) {
			return null;
		}
		List<E> nextLayerEdges = new ArrayList<>();
		for (E e : outEdges) {
			if (v.equals(e.getEnd().getSourceVertex())) {
				nextLayerEdges.add(e);
			}
		}
		Comparator<V> c = getOutgoingVertexComparator();
		nextLayerEdges.sort((e1, e2) -> c.compare(e1.getEnd(), e2.getEnd()));
		return nextLayerEdges;
	}

	private List<E> getIncommingNextLayerEdges(AbstractExplorationGraph<V, E> g, V v) {
		Collection<E> inEdges = g.getInEdges(v);
		if (inEdges == null || inEdges.isEmpty()) {
			return null;
		}
		List<E> nextLayerEdges = new ArrayList<>();
		for (E e : inEdges) {
			if (v.equals(e.getStart().getSourceVertex())) {
				nextLayerEdges.add(e);
			}
		}
		Comparator<V> c = getIncommingVertexComparator();
		nextLayerEdges.sort((e1, e2) -> c.compare(e1.getStart(), e2.getStart()));
		return nextLayerEdges;
	}

	@Override
	protected void fireVertexLocationChanged(V v, Point2D p, ChangeType type) {
		if (type == ChangeType.USER) {
			v.setUserChangedLocation(new Point2D.Double(p.getX(), p.getY()));
		}
		super.fireVertexLocationChanged(v, p, type);
	}
}
