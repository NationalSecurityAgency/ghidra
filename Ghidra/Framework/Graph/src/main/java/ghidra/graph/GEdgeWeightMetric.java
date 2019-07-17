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
package ghidra.graph;

import java.util.Comparator;

/**
 * A callback to get the weight of an edge
 * 
 * Analogous to Java's {@link Comparator}, this provides a means to override the weight of an edge
 * in a graph, or provide a weight in the absence of a natural weight, when executing various graph
 * algorithms, e.g., shortest path.
 * @param <E> the type of the edge
 */
public interface GEdgeWeightMetric<E extends GEdge<?>> {
	public static final GEdgeWeightMetric<?> UNIT_METRIC = (GEdge<?> e) -> 1;

	public static final GEdgeWeightMetric<?> NATURAL_METRIC =
		(GEdge<?> e) -> ((GWeightedEdge<?>) e).getWeight();

	/**
	 * Measure every edge as having a weight of 1
	 * @return the metric
	 */
	@SuppressWarnings("unchecked")
	public static <V, E extends GEdge<V>> GEdgeWeightMetric<E> unitMetric() {
		return (GEdgeWeightMetric<E>) UNIT_METRIC;
	}

	/**
	 * Use the natural weight of each edge
	 * 
	 * The metric assumes every edge is a {@link GWeightedEdge}. If not, you will likely encounter
	 * a {@link ClassCastException}.
	 * @return the metric
	 */
	@SuppressWarnings("unchecked")
	public static <V, E extends GEdge<V>> GEdgeWeightMetric<E> naturalMetric() {
		return (GEdgeWeightMetric<E>) NATURAL_METRIC;
	}

	/**
	 * Compute or retrieve the weight of the given edge
	 * @param e the edge
	 * @return the weight
	 */
	public double computeWeight(E e);
}
