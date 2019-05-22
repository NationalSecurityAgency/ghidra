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

import org.apache.commons.collections4.set.ListOrderedSet;

/**
 * Dependency Graph that uses {@link TreeMap}s and {@link ListOrderedSet}s to provide
 * determinism in pulling ({@link #pop()}) from the graph.  This class seems to consume more
 * memory than {@link DependencyGraph}, and if memory is not an issue, it also seems to be
 * slightly faster as well.
 * <P>
 * This class was implemented to provide determinism while doing
 * developmental debugging.
 *
 * @param <T> the type of value.
 * 
 * @see AbstractDependencyGraph
 * @see DependencyGraph
 */
public class DeterministicDependencyGraph<T> extends AbstractDependencyGraph<T> {

	public DeterministicDependencyGraph() {
		super();
	}

	/**
	 * Copy constructor
	 * @param other the other DependencyGraph to copy
	 */
	public DeterministicDependencyGraph(DeterministicDependencyGraph<T> other) {
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
	public DeterministicDependencyGraph<T> copy() {
		return new DeterministicDependencyGraph<>(this);
	}

	@Override
	protected Map<T, DependencyNode> createNodeMap() {
		return new TreeMap<>();
	}

	@Override
	protected Set<T> createNodeSet() {
		return new ListOrderedSet<>();
	}

	@Override
	protected Set<DependencyNode> createDependencyNodeSet() {
		return new ListOrderedSet<>();
	}

	@Override
	public synchronized Set<T> getNodeMapValues() {
		return ListOrderedSet.listOrderedSet(nodeMap.keySet());
	}

}
