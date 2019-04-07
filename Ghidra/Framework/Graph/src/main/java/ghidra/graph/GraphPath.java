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
 * Note: a path can only contain a vertex once.
 *
 * @param <V>
 */
public class GraphPath<V> {

	/** a set for performing quick contains checks */
	private Set<V> pathSet = new HashSet<>();
	private List<V> pathList = new ArrayList<>();

	public GraphPath() {
		// default constructor
	}

	public GraphPath(V v) {
		add(v);
	}

	public GraphPath<V> copy() {
		GraphPath<V> newPath = new GraphPath<>();
		newPath.pathList.addAll(pathList);
		newPath.pathSet.addAll(pathSet);
		return newPath;
	}

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

	public GraphPath<V> getCommonStartPath(GraphPath<V> other) {
		int n = Math.min(size(), other.size());
		for (int i = 0; i < n; i++) {
			if (!get(i).equals(other.get(i))) {
				return subPath(0, i);
			}
		}
		return subPath(0, n);
	}

	public int size() {
		return pathList.size();
	}

	public boolean contains(V v) {
		return pathSet.contains(v);
	}

	public void add(V v) {
		pathSet.add(v);
		pathList.add(v);
	}

	public V getLast() {
		return pathList.get(pathList.size() - 1);
	}

	public int depth(V v) {
		return pathList.indexOf(v);
	}

	public V get(int depth) {
		return pathList.get(depth);
	}

	public V removeLast() {
		V v = pathList.remove(pathList.size() - 1);
		pathSet.remove(v);
		return v;
	}

	/**
	 * Returns all entries that are before the given vertex in this path.  The results will
	 * include the vertex. 
	 * 
	 * @param v the vertex
	 * @return the predecessors
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
	 * Returns all entries that are later in this path than the given vertex.  The results will
	 * include the vertex.
	 * 
	 * @param v the vertex
	 * @return the successors
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

	public GraphPath<V> subPath(int start, int end) {
		GraphPath<V> subPath = new GraphPath<>();
		subPath.pathList = new ArrayList<>(pathList.subList(start, end));
		subPath.pathSet = new HashSet<>(subPath.pathList);
		return subPath;
	}

}
