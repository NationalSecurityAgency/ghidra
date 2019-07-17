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
 * Original Dependency Graph implementation that uses {@link HashMap}s and {@link HashSet}s.
 * Side affect of these is that data pulled from the graph ({@link #pop()}) is not performed
 * in a deterministic order.  However, load time for the graph is O(1).
 *
 * @param <T> the type of value.  This class uses the values as keys in HashSets, so the value
 * type must be meet the equals() and hashCode() requirements for hashing.
 * 
 * @see AbstractDependencyGraph
 * @see DeterministicDependencyGraph
 */
public class DependencyGraph<T> extends AbstractDependencyGraph<T> {

	public DependencyGraph() {
		super();
	}

	/**
	 * Copy constructor
	 * @param other the other DependencyGraph to copy
	 */
	public DependencyGraph(DependencyGraph<T> other) {
		synchronized (other) {
			for (DependencyNode node : other.nodeMap.values()) {
				addValue(node.getValue());
				if (node.getSetOfNodesThatDependOnMe() != null) {
					for (DependencyNode child : node.getSetOfNodesThatDependOnMe()) {
						addDependency(child.getValue(), node.getValue());
					}
				}
			}
		}
	}

	@Override
	public DependencyGraph<T> copy() {
		return new DependencyGraph<>(this);
	}

	@Override
	protected Map<T, DependencyNode> createNodeMap() {
		return new HashMap<>();
	}

	@Override
	protected Set<T> createNodeSet() {
		return new HashSet<>();
	}

	@Override
	protected Set<DependencyNode> createDependencyNodeSet() {
		return new HashSet<>();
	}

	@Override
	public synchronized Set<T> getNodeMapValues() {
		return new HashSet<>(nodeMap.keySet());
	}

}
