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

import java.util.*;

/**
 * Class for storing paths with fast "contains" method.
 *
 * <p>Note: a path can only contain a vertex once.
 *
 * @param <V> the vertex type.
 */
public class GraphPath<V> {

	/** a set for performing quick contains checks */
	private Set<V> pathSet = new HashSet<>();
	private List<V> pathList = new ArrayList<>();

	/**
	 * Default constructor.
	 */
	public GraphPath() {
	}

	/**
	 * Constructor with a vertex.
	 *
	 * @param v the first vertex of the newly initialized GraphPath object
	 */
	public GraphPath(V v) {
		add(v);
	}

	/**
	 * Creates a new GraphPath object by performing a shallow copy on another GraphPath object.
	 *
	 * @return the new shallow copy of the original GraphPath object
	 */
	public GraphPath<V> copy() {
		GraphPath<V> newPath = new GraphPath<>();
		newPath.pathList.addAll(pathList);
		newPath.pathSet.addAll(pathSet);
		return newPath;
	}

	/**
	 * Check if a GraphPath starts with another GraphPath.
	 *
	 * @param otherPath the other GraphPath we are checking
	 * @return true if the current GraphPath starts with otherPath, false otherwise
	 */
	public boolean startsWith(GraphPath<V> otherPath) {
		if (size() < otherPath.size()) {
			return false;
		}

		for (int i = 0; i < otherPath.size(); i++) {
			if (!pathList.get(i).equals(otherPath.pathList.get(i))) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Return all vertices that two GraphPaths have in common. For example if you have
	 * a-b-c-d-e-f and a-b-c-d-k-l-z, the common start path will be a-b-c-d. If there is no common
	 * start path, an empty GraphPath object is returned.
	 *
	 * @param other the other GraphPath to get the common start path of
	 * @return a new GraphPath object containing the common start path vertices
	 */
	public GraphPath<V> getCommonStartPath(GraphPath<V> other) {
		int n = Math.min(size(), other.size());
		for (int i = 0; i < n; i++) {
			if (!get(i).equals(other.get(i))) {
				return subPath(0, i);
			}
		}
		return subPath(0, n);
	}

	/**
	 * Return the size of the GraphPath.
	 *
	 * @return size of the GraphPath
	 */
	public int size() {
		return pathList.size();
	}

	/**
	 * Check if vertex v is in the GraphPath.
	 *
	 * @param v the vertex
	 * @return true if vertex v is in this GraphPath
	 */
	public boolean contains(V v) {
		return pathSet.contains(v);
	}

	/**
	 * Add a vertex to the GraphPath.
	 *
	 * @param v the new vertex
	 */
	public void add(V v) {
		pathSet.add(v);
		pathList.add(v);
	}

	/**
	 * Get last vertex of GraphPath.
	 *
	 * @return last vertex of GraphPath
	 */
	public V getLast() {
		return pathList.get(pathList.size() - 1);
	}

	/**
	 * Get the depth of the vertex that is specified by the parameter.
	 *
	 * @param v the vertex for which we get the depth
	 * @return the depth of the vertex
	 */
	public int depth(V v) {
		return pathList.indexOf(v);
	}

	/**
	 * Get vertex that is specified by the parameter.
	 *
	 * @param depth of the vertex to retrieve
	 * @return the vertex
	 */
	public V get(int depth) {
		return pathList.get(depth);
	}

	/**
	 * Remove the last vertex of the GraphPath.
	 *
	 * @return the removed vertex
	 */
	public V removeLast() {
		V v = pathList.remove(pathList.size() - 1);
		pathSet.remove(v);
		return v;
	}

	/**
	 * Return a set with all of the predecessors of the vertex in the GraphPath.
	 *
	 * @param v the vertex we want to get the predecessors of
	 * @return the predecessors of the vertex as a set, return empty set if there are none
	 */
	public Set<V> getPredecessors(V v) {
		Set<V> set = new HashSet<>();
		int index = pathList.indexOf(v);
		if (index < 0) {
			return set;
		}

		set.addAll(pathList.subList(0, index + 1)); // include the vertex
		return set;
	}

	/**
	 * Return a set with all of the successors of the vertex in the GraphPath.
	 *
	 * @param v the vertex we want to get the successors of
	 * @return the successors of the vertex as a set, return empty set if there are none
	 */
	public Set<V> getSuccessors(V v) {
		Set<V> set = new HashSet<>();
		int index = pathList.indexOf(v);
		if (index < 0) {
			return set;
		}

		set.addAll(pathList.subList(index, pathList.size())); // include the vertex

		return set;
	}

	@Override
	public String toString() {
		return pathList.toString();
	}

	/**
	 * Get a part of the whole GraphPath, similar to substring with strings.
	 *
	 * @param start the start of the sub-path of the GraphPath
	 * @param end the end of the sub-path of the GraphPath
	 * @return a new GraphPath which is a sub-path of the original GraphPath from start to end
	 */
	public GraphPath<V> subPath(int start, int end) {
		GraphPath<V> subPath = new GraphPath<>();
		subPath.pathList = new ArrayList<>(pathList.subList(start, end));
		subPath.pathSet = new HashSet<>(subPath.pathList);
		return subPath;
	}

}
