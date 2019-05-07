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
package ghidra.util.graph;

import java.util.*;

/**
 * Class for managing the visiting (processing)  of a set of values where some values depend
 * on other values being process before them.  In other words, an acyclic directed graph will
 * be formed where the vertexes are the values and the edges represent dependencies.  Values can
 * only be removed if they have no dependencies.  Since the graph is acyclic, as values are removed
 * that have no dependencies, other nodes that depend on those nodes will become eligible for 
 * processing and removal.  If cycles are introduced, they will eventually cause an IllegalState
 * exception to occur when removing and processing values.  There is also a hasCycles() method
 * that can be called before processing to find cycle problems up front without wasting time 
 * processing values. 
 *
 * @param <T> the type of value.  Some concrete classes might have restrictions on T.
 * 
 * @see DependencyGraph
 * @see DeterministicDependencyGraph
 */
public abstract class AbstractDependencyGraph<T> {
	protected Map<T, DependencyNode> nodeMap;
	protected Set<T> unvisitedIndependentSet;
	private int visitedButNotDeletedCount = 0;

	public AbstractDependencyGraph() {
		nodeMap = createNodeMap();
		unvisitedIndependentSet = createNodeSet();
	}

	public Map<T, DependencyNode> getNodeMap() {
		return nodeMap;
	}

	/**
	 * Creates the Map of Nodes to {@link DependencyNode}s appropriate for the implementer.
	 * @return a new Map of Nodes to {@link DependencyNode}s.
	 */
	protected abstract Map<T, DependencyNode> createNodeMap();

	/**
	 * Creates the Set of Nodes appropriate for the implementer.
	 * @return a new Set of Nodes.
	 */
	protected abstract Set<T> createNodeSet();

	/**
	 * Creates the Set of {@link DependencyNode}s appropriate for the implementer.
	 * @return a new Set of {@link DependencyNode}s.
	 */
	protected abstract Set<DependencyNode> createDependencyNodeSet();

	/**
	 * Returns a copy of this graph.
	 * @return a copy of this graph.
	 */
	public abstract AbstractDependencyGraph<T> copy();

	/**
	 * Copy constructor
	 * Cannot be abstracted here.  Each individual implementer must implement their own.
	 * @param other the other DependencyGraph to copy
	 */

	/**
	 * Adds the value to this graph.
	 * @param value the value to add
	 */
	public synchronized void addValue(T value) {
		getOrCreateDependencyNode(value);
	}

	/**
	 * Returns the number of values in this graph.
	 * @return the number of values in this graph.
	 */
	public synchronized int size() {
		return nodeMap.size();
	}

	/**
	 * Returns true if the graph has no values;
	 * @return true if the graph has no values;
	 */
	public synchronized boolean isEmpty() {
		return nodeMap.isEmpty();
	}

	/**
	 * Returns true if this graph has the given key.
	 * @param value the value to check if its in this graph
	 * @return true if this graph has the given key.
	 */
	public synchronized boolean contains(T value) {
		return nodeMap.containsKey(value);
	}

	/**
	 * Returns the set of values in this graph.
	 * @return the set of values in this graph.
	 */
	public synchronized Set<T> getValues() {
		return new HashSet<>(nodeMap.keySet());
	}

	/**
	 * Returns the set of values in this graph.
	 * @return the set of values in this graph.
	 */
	public abstract Set<T> getNodeMapValues();

	private DependencyNode getOrCreateDependencyNode(T value) {
		DependencyNode dependencyNode = nodeMap.get(value);
		if (dependencyNode == null) {
			dependencyNode = new DependencyNode(value);
			nodeMap.put(value, dependencyNode);
			unvisitedIndependentSet.add(value);
		}
		return dependencyNode;
	}

	/**
	 * Add a dependency such that value1 depends on value2.  Both value1 and value2 will be
	 * added to the graph if they are not already in the graph.
	 * @param value1 the value that depends on value2
	 * @param value2 the value that value1 is depending on
	 */
	public synchronized void addDependency(T value1, T value2) {
		DependencyNode valueNode1 = getOrCreateDependencyNode(value1);
		DependencyNode valueNode2 = getOrCreateDependencyNode(value2);
		valueNode2.addNodeThatDependsOnMe(valueNode1);

	}

	/**
	 * Returns true if there are unvisited values ready (no dependencies) for processing.
	 * 
	 * @return true if there are unvisited values ready for processing.
	 * 
	 * @exception IllegalStateException is thrown if the graph is not empty and there are no nodes
	 * without dependency which indicates there is a cycle in the graph.
	 */
	public synchronized boolean hasUnVisitedIndependentValues() {
		if (!unvisitedIndependentSet.isEmpty()) {
			return true;
		}
		checkCycleState();
		return false;
	}

	/**
	 * Removes and returns a value that has no dependencies from the graph.  If the graph is empty
	 * or all the nodes without dependencies are currently visited, then null will be returned.
	 * NOTE: If the getUnvisitedIndependentValues() method has been called(), this method may
	 * return null until all those "visited" nodes are removed from the graph.  
	 * @return return an arbitrary value that has no dependencies and hasn't been visited or null.
	 */
	public synchronized T pop() {
		checkCycleState();
		if (unvisitedIndependentSet.isEmpty()) {
			return null;
		}
		T value = unvisitedIndependentSet.iterator().next();
		unvisitedIndependentSet.remove(value);
		remove(value);
		return value;
	}

	private void checkCycleState() {
		if (!isEmpty() && unvisitedIndependentSet.isEmpty() && visitedButNotDeletedCount == 0) {
			throw new IllegalStateException("Cycle detected!");
		}
	}

	/**
	 * Checks if this graph has cycles.  Normal processing of this graph will eventually reveal
	 * a cycle and throw an exception at the time it is detected.  This method allows for a 
	 * "fail fast" way to detect cycles.
	 * @return true if cycles exist in the graph.
	 */
	public synchronized boolean hasCycles() {
		try {
			Set<T> visited = createNodeSet();

			while (!unvisitedIndependentSet.isEmpty()) {
				Collection<T> values = getUnvisitedIndependentValues();
				visited.addAll(values);

				for (T k : values) {
					DependencyNode node = nodeMap.get(k);
					node.releaseDependencies();
				}
			}
			if (visited.size() != nodeMap.size()) {
				return true;
			}
		}
		finally {
			reset();
		}
		return false;
	}

	private void reset() {
		visitedButNotDeletedCount = 0;
		for (DependencyNode node : nodeMap.values()) {
			node.numberOfNodesThatIDependOn = 0;
		}
		for (DependencyNode node : nodeMap.values()) {
			if (node.setOfNodesThatDependOnMe != null) {
				for (DependencyNode child : node.setOfNodesThatDependOnMe) {
					unvisitedIndependentSet.remove(child.value);
					child.numberOfNodesThatIDependOn++;
				}
			}
		}
		unvisitedIndependentSet = getAllIndependentValues();
	}

	/**
	 * Returns a set of all values that have no dependencies.  As values are removed from the
	 * graph, dependencies will be removed and additional values will be eligible to be returned
	 * by this method.  Once a value has been retrieved using this method, it will be considered
	 * "visited" and future calls to this method will not include those values.  To continue
	 * processing the values in the graph, all values return from this method should eventually
	 * be deleted from the graph to "free up" other values.  NOTE: values retrieved by this method
	 * will no longer be eligible for return by the pop() method. 
	 *
	 * @return the set of values without dependencies that have never been returned by this method 
	 * before.
	 */
	public synchronized Set<T> getUnvisitedIndependentValues() {
		checkCycleState();
		visitedButNotDeletedCount += unvisitedIndependentSet.size();
		Set<T> returnCollection = unvisitedIndependentSet;
		unvisitedIndependentSet = createNodeSet();
		return returnCollection;
	}

	/**
	 * Returns the set of all values that have no dependencies regardless of whether or not
	 * they have been "visited" (by the getUnvisitedIndependentValues() method.
	 * @return return the set of all values that have no dependencies.
	 */
	public synchronized Set<T> getAllIndependentValues() {
		Set<T> set = createNodeSet();
		for (DependencyNode node : nodeMap.values()) {
			if (node.numberOfNodesThatIDependOn == 0) {
				set.add(node.value);
			}
		}
		return set;
	}

	/**
	 * Removes the value from the graph.  Any dependency from this node to another will be removed,
	 * possible allowing nodes that depend on this node to be eligible for processing.
	 * @param value the value to remove from the graph.
	 */
	public synchronized void remove(T value) {
		DependencyNode node = nodeMap.remove(value);
		if (node != null) {
			node.releaseDependencies();
			if (unvisitedIndependentSet.remove(value)) {
				visitedButNotDeletedCount--;
			}
		}
	}

	/**
	 * Returns a set of values that depend on the given value.
	 * @param value the value that other values may depend on.
	 * @return a set of values that depend on the given value.
	 */
	public synchronized Set<T> getDependentValues(T value) {
		Set<T> set = createNodeSet();

		DependencyNode node = nodeMap.get(value);
		if (node != null && node.setOfNodesThatDependOnMe != null) {
			for (DependencyNode child : node.setOfNodesThatDependOnMe) {
				set.add(child.value);
			}
		}
		return set;
	}

	protected class DependencyNode {
		private final T value;
		private Set<DependencyNode> setOfNodesThatDependOnMe;
		private int numberOfNodesThatIDependOn = 0;

		DependencyNode(T value) {
			this.value = value;
		}

		public T getValue() {
			return value;
		}

		public Set<DependencyNode> getSetOfNodesThatDependOnMe() {
			return setOfNodesThatDependOnMe;
		}

		public int getNumberOfNodesThatIDependOn() {
			return numberOfNodesThatIDependOn;
		}

		public void releaseDependencies() {
			if (setOfNodesThatDependOnMe == null) {
				return;
			}
			for (DependencyNode node : setOfNodesThatDependOnMe) {
				if (--node.numberOfNodesThatIDependOn == 0) {
					unvisitedIndependentSet.add(node.value);
				}
			}
		}

		public void addNodeThatDependsOnMe(DependencyNode node) {
			if (setOfNodesThatDependOnMe == null) {
				setOfNodesThatDependOnMe = createDependencyNodeSet();
			}

			if (setOfNodesThatDependOnMe.add(node)) {
				// if not already added, increment the dependent node's count so that it knows
				// how many nodes it depends on.
				node.numberOfNodesThatIDependOn++;

				unvisitedIndependentSet.remove(node.value);  // it has at least one dependency now
			}
		}

		@Override
		public String toString() {
			return value == null ? "" : value.toString();
		}
	}

}
