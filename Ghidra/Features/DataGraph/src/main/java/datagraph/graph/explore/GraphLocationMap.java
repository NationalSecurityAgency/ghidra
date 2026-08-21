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

import java.awt.Point;
import java.awt.geom.Point2D;
import java.util.*;

/**
 * Map of vertex locations in layout space and the boundaries for the space this sub graph
 * occupies.
 *
 * @param <V> the vertex type
 */
public class GraphLocationMap<V> {
	private Map<V, Point> vertexPoints = new HashMap<>();
	private int minX;
	private int maxX;
	private int minY;
	private int maxY;

	/**
	 * Constructs a map with exactly one vertex which is located at P(0,0). The size of the vertex
	 * determines the map's bounds.
	 * @param vertex the initial vertex
	 * @param width the width of the the verte.  
	 * @param height the height of the vertex
	 */
	public GraphLocationMap(V vertex, int width, int height) {
		vertexPoints.put(vertex, new Point(0, 0));
		this.maxX = (width + 1) / 2;	// add 1 so that odd sizes have the extra size to the right
		this.minX = -width / 2;
		this.maxY = (height + 1) / 2; 	// add 1 so that odd sizes have the extra size to the bottom
		this.minY = -height / 2;
	}

	/**
	 * Merges another {@link GraphLocationMap} into this one shifting its bounds and bounds by the
	 * given shift values. When this completes, the other map is disposed.
	 * @param other the other GridLocationMap to merge into this one
	 * @param xShift the amount to shift the other map horizontally before merging.
	 * @param yShift the amount to shift the other map vertically before merging.
	 */
	public void merge(GraphLocationMap<V> other, int xShift, int yShift) {
		other.shift(xShift, yShift);
		vertexPoints.putAll(other.vertexPoints);

		this.minX = Math.min(minX, other.minX);
		this.maxX = Math.max(maxX, other.maxX);
		this.minY = Math.min(minY, other.minY);
		this.maxY = Math.max(maxY, other.maxY);
		other.dispose();
	}

	private void dispose() {
		vertexPoints.clear();
	}

	private void shift(int xShift, int yShift) {
		Collection<Point> values = vertexPoints.values();
		for (Point point : values) {
			point.x += xShift;
			point.y += yShift;
		}
		maxX += xShift;
		minX += xShift;
		maxY += yShift;
		minY += yShift;
	}

	/**
	 * {@return the width of this map. This includes space for the size of vertices and not just
	 * their center points.}
	 */
	public int getWidth() {
		return maxX - minX;
	}

	/**
	 * {@return the height of this map. This includes space for the size of vertices and not just
	 * their center points.}
	 */
	public int getHeight() {
		return maxY - minY;
	}

	/**
	 * {@return the location for the given vertex.}
	 * @param v the vertex to get a location for
	 */
	public Point get(V v) {
		return vertexPoints.get(v);
	}

	/**
	 * {@return a map of the vertices and their locations.}
	 */
	public Map<V, Point2D> getVertexLocations() {
		Map<V, Point2D> points = new HashMap<>();
		points.putAll(vertexPoints);
		return points;
	}

	/**
	 * {@return the minimum x coordinate of the graph.}
	 */
	public int getMinX() {
		return minX;
	}

	/**
	 * {@return the maximum x coordinate of the graph.}
	 */
	public int getMaxX() {
		return maxX;
	}
}
