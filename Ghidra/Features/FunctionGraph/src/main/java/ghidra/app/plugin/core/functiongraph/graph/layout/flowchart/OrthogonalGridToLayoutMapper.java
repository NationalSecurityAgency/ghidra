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
package ghidra.app.plugin.core.functiongraph.graph.layout.flowchart;

import java.awt.Rectangle;
import java.awt.Shape;
import java.awt.geom.Point2D;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.Function;

import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import ghidra.graph.viewer.layout.*;

/**
 * Maps the grid points of vertices and edges in a {@link GridLocationMap} to x,y locations in
 * layout space. The mapping is specifically for grids that contain edges that have been given
 * orthogonally routed articulation points.
 * <P>  
 * First the edges have to be organized into row and column segments so that overlapping segments
 * can be assigned offsets from the grid lines so that they won't overlap in layout space. Also,
 * the offset information is need to provide "thickness" for the edges in a row or column.
 * Next, the grid size and positioning in layout space is computed. Finally, it is a simple matter
 * to translate grid points for vertices directly into points in layout space. Edge points are
 * similar, but they need to add their assigned offset for each segment to its corresponding
 * translated grid articulation point. 
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class OrthogonalGridToLayoutMapper<V extends VisualVertex, E extends VisualEdge<V>> {
	private static final int EDGE_SPACING = 7;
	private static final int CONDENSED_EDGE_SPACING = 5;

	private EdgeSegmentMap<E> segmentMap;
	private GridLocationMap<V, E> grid;
	private Function<V, Shape> transformer;
	private GridCoordinates gridCoordinates;
	private int edgeSpacing;

	public OrthogonalGridToLayoutMapper(GridLocationMap<V, E> grid, Function<V, Shape> transformer,
			boolean isCondensed) {
		this.grid = grid;
		this.transformer = transformer;
		this.edgeSpacing = isCondensed ? CONDENSED_EDGE_SPACING : EDGE_SPACING;

		// organize the edge articulations into segments by row and column 
		segmentMap = new EdgeSegmentMap<E>(grid);

		// compute row and column sizes
		OrthogonalGridSizer<V, E> sizer =
			new OrthogonalGridSizer<>(grid, segmentMap, transformer, edgeSpacing);

		// get the grid coordinates from the sizer.
		gridCoordinates = sizer.getGridCoordinates(isCondensed);
	}

	/**
	 * Returns a map of vertices to points in layout space.
	 * @return a map of vertices to points in layout space
	 */
	public Map<V, Point2D> getVertexLocations() {

		Map<V, Point2D> vertexLocations = new HashMap<>();

		for (Entry<V, GridPoint> entry : grid.getVertexPoints().entrySet()) {
			V v = entry.getKey();
			GridPoint p = entry.getValue();

			Shape shape = transformer.apply(v);
			Rectangle vertexBounds = shape.getBounds();
			int x = gridCoordinates.x(p.col);
			int y = gridCoordinates.y(p.row) + (vertexBounds.height >> 1);

			Point2D location = new Point2D.Double(x, y);
			vertexLocations.put(v, location);
		}
		return vertexLocations;
	}

	/**
	 * Returns a map of edges to lists of articulation points in layout space.
	 * @param vertexLocations the locations of vertices already mapped in layout space.
	 * @return  a map of edges to lists of articulation points in layout space
	 */
	public Map<E, List<Point2D>> getEdgeLocations(Map<V, Point2D> vertexLocations) {
		Map<E, List<Point2D>> edgeLocations = new HashMap<>();
		for (E edge : grid.edges()) {

			List<GridPoint> gridPoints = grid.getArticulations(edge);
			List<Point2D> points = new ArrayList<>(gridPoints.size());

			GridPoint gp = gridPoints.get(0);
			EdgeSegment<E> edgeSegment = segmentMap.getColumnSegment(edge, gp);

			int offset = edgeSegment.getOffset();
			double x = gridCoordinates.x(gp.col) + offset * edgeSpacing;
			double y = vertexLocations.get(edge.getStart()).getY();
			points.add(new Point2D.Double(x, y));

			for (int i = 1; i < gridPoints.size() - 1; i++) {
				edgeSegment = edgeSegment.nextSegment();
				gp = gridPoints.get(i);
				if (i % 2 == 0) {
					offset = edgeSegment.getOffset();
					x = gridCoordinates.x(gp.col) + offset * edgeSpacing;
					points.add(new Point2D.Double(x, y));

				}
				else {
					offset = edgeSegment.getOffset();
					y = gridCoordinates.y(gp.row) + offset * edgeSpacing;
					points.add(new Point2D.Double(x, y));
				}
			}
			gp = gridPoints.get(gridPoints.size() - 1);
			y = vertexLocations.get(edge.getEnd()).getY();
			points.add(new Point2D.Double(x, y));
			edgeLocations.put(edge, points);
		}

		return edgeLocations;
	}

	/**
	 * Returns the computed grid coordinates.
	 * @return the computed grid coordinates
	 */
	public GridCoordinates getGridCoordinates() {
		return gridCoordinates;
	}

	public List<Integer> getEdgeOffsets(E edge) {
		List<Integer> offsets = new ArrayList<>();
		List<GridPoint> gridPoints = grid.getArticulations(edge);

		GridPoint gp = gridPoints.get(0);
		EdgeSegment<E> edgeSegment = segmentMap.getColumnSegment(edge, gp);
		while (edgeSegment != null) {
			offsets.add(edgeSegment.getOffset());
			edgeSegment = edgeSegment.nextSegment();
		}
		return offsets;
	}

	public void dispose() {
		segmentMap.dispose();
		grid.dispose();
		gridCoordinates = null;
	}
}
