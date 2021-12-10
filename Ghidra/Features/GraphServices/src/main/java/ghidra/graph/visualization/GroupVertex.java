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
package ghidra.graph.visualization;

import java.util.*;
import java.util.stream.Collectors;

import ghidra.service.graph.AttributedVertex;

/**
 * AttributedVertex class to represent a group of "collapsed nodes"
 */
public class GroupVertex extends AttributedVertex {
	private static final int MAX_IDS_TO_COMBINE = 6;
	private Set<AttributedVertex> children;
	private AttributedVertex first;

	/**
	 * Creates a new GroupVertex that represents the grouping of the given vertices.
	 * @param vertices the nodes to be grouped.
	 * @return a new GroupVertex.
	 */
	public static GroupVertex groupVertices(Collection<AttributedVertex> vertices) {

		// the set of vertices given may include group nodes, we only want "real nodes"
		Set<AttributedVertex> set = flatten(vertices);
		List<AttributedVertex> list = new ArrayList<>(set);
		Collections.sort(list, Comparator.comparing(AttributedVertex::getName));
		return new GroupVertex(set, getUniqueId(list), list.get(0));
	}

	private GroupVertex(Set<AttributedVertex> children, String id, AttributedVertex first) {
		super(id);
		this.first = first;
		this.children = children;
		setVertexType("Collapsed Group");
	}

	/**
	 * Returns a set of vertices such that all non-group nodes in the given vertices are included
	 * and any group nodes in the given vertices are replaced with their contained vertices.
	 * 
	 * @param vertices the collection of vertices to flatten into a set of non-group vertices.
	 * @return a set of non-group vertices derived from the given collection where all the group
	 * vertices have been replace with their contained vertices.
	 */
	public static Set<AttributedVertex> flatten(Collection<AttributedVertex> vertices) {
		Set<AttributedVertex> set = new HashSet<>();
		for (AttributedVertex vertex : vertices) {
			if (vertex instanceof GroupVertex) {
				set.addAll(((GroupVertex) vertex).children);
			}
			else {
				set.add(vertex);
			}
		}
		return set;
	}

	private static String getUniqueId(List<AttributedVertex> vertexList) {
		if (vertexList.size() > MAX_IDS_TO_COMBINE) {
			int idsNotShownCount = vertexList.size() - MAX_IDS_TO_COMBINE;
			return combineIds(vertexList.subList(0, MAX_IDS_TO_COMBINE)) + "\n...\n + " +
				idsNotShownCount + " Others";
		}
		return combineIds(vertexList);
	}

	private static String combineIds(Collection<AttributedVertex> vertices) {
		return vertices.stream().map(AttributedVertex::getName).collect(Collectors.joining("\n"));
	}

	/** 
	 * Returns the set of flattened nodes contained in this node.  In other words, any group nodes
	 * that were given to this group node would have been swapped for the nodes that the groupd node
	 * contained.
	 * 
	 * @return the set of flattened graph vertices represented by this group node.
	 */
	public Set<AttributedVertex> getContainedVertices() {
		return Collections.unmodifiableSet(children);
	}

	/**
	 * Returns the node that is first, with first being currently defined to be the one that is 
	 * first when sorted by id alphabetically.
	 * 
	 * @return the node that is first.
	 */
	public AttributedVertex getFirst() {
		return first;
	}

}
