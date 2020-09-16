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
package ghidra.graph.algo;

import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.collections4.map.LazyMap;

import generic.util.DequePush;
import ghidra.generic.util.datastruct.TreeValueSortedMap;
import ghidra.generic.util.datastruct.ValueSortedMap;
import ghidra.graph.*;

/**
 * Dijkstra's shortest-path algorithm
 * 
 * <p>
 * This implementation computes the shortest paths between two vertices using Dijkstra's
 * single-source shortest path finding algorithm. Any time a new source is given, it explores all
 * destinations in the graph up to a maximum distance from the source. Thus, this implementation is
 * best applied when many queries are anticipated from relatively few sources.
 *
 * @param <V> the type of vertices
 * @param <E> the type of edges
 */
public class DijkstraShortestPathsAlgorithm<V, E extends GEdge<V>> {
	protected final Map<V, OneSourceToAll> sources =
		LazyMap.lazyMap(new HashMap<>(), (V src) -> new OneSourceToAll(src));
	protected final GImplicitDirectedGraph<V, E> graph;
	protected final double maxDistance;
	protected final GEdgeWeightMetric<E> metric;

	/**
	 * Use Dijkstra's algorithm on the given graph
	 * 
	 * <p>
	 * This constructor assumes the graph's edges are {@link GWeightedEdge}s. If not, you will
	 * likely encounter a {@link ClassCastException}.
	 * 
	 * @param graph the graph
	 */
	public DijkstraShortestPathsAlgorithm(GImplicitDirectedGraph<V, E> graph) {
		this.graph = graph;
		this.maxDistance = Double.POSITIVE_INFINITY;
		this.metric = GEdgeWeightMetric.naturalMetric();
	}

	/**
	 * Use Dijkstra's algorithm on the given graph with the given maximum distance
	 * 
	 * <p>
	 * This constructor assumes the graph's edges are {@link GWeightedEdge}s. If not, you will
	 * likely encounter a {@link ClassCastException}.
	 * 
	 * @param graph the graph
	 * @param maxDistance the maximum distance, or null for no maximum
	 */
	public DijkstraShortestPathsAlgorithm(GImplicitDirectedGraph<V, E> graph, double maxDistance) {
		this.graph = graph;
		this.maxDistance = maxDistance;
		this.metric = GEdgeWeightMetric.naturalMetric();
	}

	/**
	 * Use Dijstra's algorithm on the given graph with a custom edge weight metric
	 * 
	 * @param graph the graph
	 * @param metric the function to compute the weight of an edge
	 */
	public DijkstraShortestPathsAlgorithm(GImplicitDirectedGraph<V, E> graph,
			GEdgeWeightMetric<E> metric) {
		this.graph = graph;
		this.maxDistance = Double.POSITIVE_INFINITY;
		this.metric = metric;
	}

	/**
	 * Use Dijstra's algorithm on the given graph with the given maximum distance and a custom edge
	 * weight metric
	 * 
	 * @param graph the graph
	 * @param maxDistance the maximum distance, or null for no maximum
	 * @param metric the function to compute the weight of an edge
	 */
	public DijkstraShortestPathsAlgorithm(GImplicitDirectedGraph<V, E> graph, double maxDistance,
			GEdgeWeightMetric<E> metric) {
		this.graph = graph;
		this.maxDistance = maxDistance;
		this.metric = metric;
	}

	/**
	 * Compute the shortest distance to all reachable vertices from the given source
	 * 
	 * @param v the source vertex
	 * @return a map of destinations to distances from the given source
	 */
	public Map<V, Double> getDistancesFromSource(V v) {
		OneSourceToAll info = sources.get(v);
		return Collections.unmodifiableMap(info.visitedDistance);
	}

	/**
	 * Compute the shortest paths from the given source to the given destination
	 * 
	 * <p>
	 * This implementation differs from typical implementations in that paths tied for the shortest
	 * distance are all returned. Others tend to choose one arbitrarily.
	 * 
	 * @param src the source
	 * @param dst the destination
	 * @return a collection of paths of shortest distance from source to destination
	 */
	public Collection<Deque<E>> computeOptimalPaths(V src, V dst) {
		return sources.get(src).computeOptimalPathsTo(dst);
	}

	/**
	 * A class representing all optimal paths from a given source to every other (reachable) vertex
	 * in the graph
	 * 
	 * <p>
	 * This is the workhorse of path computation, and implements Dijkstra's Shortest Path algorithm
	 * from one source to all destinations. We considered using JUNG to store the graph and compute
	 * the paths, but we could not, because we would like to find all paths having the optimal
	 * distance. If there are ties, JUNG's implementation chooses one arbitrarily; we would like all
	 * tied paths.
	 */
	protected class OneSourceToAll {
		// For explored, but unvisited nodes
		protected final ValueSortedMap<V, Double> queueByDistance =
			TreeValueSortedMap.createWithNaturalOrder();
		// For visited nodes, i.e., their optimal distance is known
		protected final Map<V, Double> visitedDistance = new LinkedHashMap<>();
		protected final Map<V, Set<E>> bestIns =
			LazyMap.lazyMap(new HashMap<>(), () -> new HashSet<>());

		protected final V source;

		/**
		 * Compute the shortest paths from a given vertex to all other reachable vertices in the
		 * graph
		 * 
		 * @param src the source (seed) vertex
		 */
		protected OneSourceToAll(V src) {
			this.source = src;
			queueByDistance.put(src, 0d);
			fill();
		}

		/**
		 * Recover the shortest paths from the source to the given destination, if it is reachable
		 * 
		 * @param dst the destination
		 * @return a collection of the shortest paths from source to destination, or the empty set
		 */
		public Collection<Deque<E>> computeOptimalPathsTo(V dst) {
			Set<Deque<E>> paths = new HashSet<>();
			addPathsTo(paths, dst);
			return paths;
		}

		/**
		 * Add the shortest paths from the source to the given destination into the given collection
		 * 
		 * <p>
		 * This is used internally to recover the shortest paths
		 * 
		 * @param paths a place to store the recovered paths
		 * @param dst the destination
		 */
		protected void addPathsTo(Collection<Deque<E>> paths, V dst) {
			addPathsTo(paths, dst, new LinkedList<>());
		}

		/**
		 * Add the shortest paths from source to a given intermediate, continuing along a given path
		 * to the final destination, into the given collection
		 * 
		 * <p>
		 * This is a recursive method for constructing the shortest paths overall. Assuming the
		 * given path from intermediate to final destination is the shortest, we can show by
		 * induction, the computed paths from source to destination are the shortest.
		 * 
		 * @param paths a place to store the recovered paths
		 * @param prev the intermediate destination
		 * @param soFar a (shortest) path from intermediate to final destination
		 */
		protected void addPathsTo(Collection<Deque<E>> paths, V prev, Deque<E> soFar) {
			if (prev.equals(source)) { // base case:
				// The path from source to source is empty, and our path from intermediate to
				// destination is actually the path from source to destination. Add it!
				paths.add(new LinkedList<>(soFar));
			}
			else { // inductive case:
				/*
				 * Dijkstra has computed the best inbound edges. Consider each as a prefix to the
				 * current path from intermediate to final destination. Since we assume that path is
				 * an optimal path, and we prefix an optimal inbound edge, the prefixed path is an
				 * optimal path from a new intermediate source (inbound neighbor) to the final
				 * destination. So, just recurse, using the new intermediates.
				 */
				for (E e : bestIns.get(prev)) {
					V nextPrev = e.getStart();
					try (DequePush<?> push = DequePush.push(soFar, e)) {
						addPathsTo(paths, nextPrev, soFar);
					}
				}
			}
		}

		/**
		 * Update the record for the given destination with a new offer of shortest distance
		 * 
		 * <p>
		 * If either the record doesn't exist yet, or the new offer beats the current best, then a
		 * new record is created and replaces the current record. If present, the list of best
		 * inbound edges is cleared -- because they all correspond to a distance that has just been
		 * beat. The node is also added and/or moved forward in the queue of unvisited vertices.
		 * 
		 * <p>
		 * If the record exists, and the new offer ties the current offer, nothing happens, but the
		 * method still returns true, since the corresponding inbound edge could be optimal.
		 * 
		 * <p>
		 * If the record's current best beats the offer, nothing happens, and the method returns
		 * false, indicating the inbound edge is definitely not optimal.
		 * 
		 * @param dest the destination whose record to update
		 * @param newDist the distance offer
		 * @return true iff the offer is equal to or better than the record's current best
		 */
		protected boolean addOrUpdate(V dest, double newDist) {
			// Is it already visited?
			Double curDist = visitedDistance.get(dest);
			if (curDist != null) {
				return false;
			}
			// Nope? Well let's update the records.
			curDist = queueByDistance.get(dest);
			if (curDist == null) {
				queueByDistance.put(dest, newDist);
				return true;
			}
			else if (newDist < curDist) {
				queueByDistance.put(dest, newDist);
				bestIns.get(dest).clear();
				return true;
			}
			else if (newDist == curDist) {
				return true;
			}
			return false;
		}

		/**
		 * Compute paths, building out the graph until all reachable vertices have been visited
		 */
		protected void fill() {
			Entry<V, Double> next;
			while ((next = queueByDistance.entrySet().poll()) != null) {
				// Mark it visited, and save the distance (may not need distance anymore....)
				visitedDistance.put(next.getKey(), next.getValue());
				fillStep(next.getKey(), next.getValue());
			}
		}

		/**
		 * Perform one iteration of Dijskstra's path finding algorithm
		 * 
		 * @param from the vertex to visit for this iteration
		 */
		protected void fillStep(V from, double dist) {
			for (E e : graph.getOutEdges(from)) {
				double newDist = dist + metric.computeWeight(e);
				if (newDist > maxDistance) {
					continue;
				}
				V dest = e.getEnd();
				if (addOrUpdate(dest, newDist)) {
					bestIns.get(dest).add(e);
				}
			}
		}
	}
}
