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
package ghidra.service.graph;

import java.util.*;

/**
 * Class that defines a new graph type. It defines the set of valid vertex and edge types
 */
public class GraphType {
	private final String name;
	private final String description;

	private final Set<String> vertexTypes;
	private final Set<String> edgeTypes;

	/**
	 * Constructs a new GraphType
	 * 
	 * @param name the name of this GraphType instance
	 * @param description a brief description for graphs of this type
	 * @param vertexTypes a list of all valid vertex types for graphs of this type
	 * @param edgeTypes a list of all valid edge types for graphs of this type
	 */
	public GraphType(String name, String description, List<String> vertexTypes,
			List<String> edgeTypes) {
		this.name = Objects.requireNonNull(name);
		this.description = Objects.requireNonNull(description);

		this.vertexTypes = Collections.unmodifiableSet(new LinkedHashSet<String>(vertexTypes));
		this.edgeTypes = Collections.unmodifiableSet(new LinkedHashSet<String>(edgeTypes));
	}

	/**
	 * Returns a name for this type of graph
	 * @return a name of this type of graph
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns a description for this type of graph
	 * @return a description for this type of graph
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Returns a list of valid vertex types for graphs of this type
	 * @return a list of valid vertex types for graphs of this type
	 */
	public List<String> getVertexTypes() {
		return new ArrayList<>(vertexTypes);
	}

	/**
	 * Returns a list of valid edge types for graphs of this type
	 * @return a list of valid edge types for graphs of this type
	 */
	public List<String> getEdgeTypes() {
		return new ArrayList<>(edgeTypes);
	}

	/**
	 * Test if the given string is a valid vertex type
	 * @param vertexType the string to test for being a valid vertex type
	 * @return true if the given string is a valid vertex type
	 */
	public boolean containsVertexType(String vertexType) {
		return vertexTypes.contains(vertexType);
	}

	/**
	 * Test if the given string is a valid edge type
	 * @param edgeType the string to test for being a valid edge type
	 * @return true if the given string is a valid edge type
	 */
	public boolean containsEdgeType(String edgeType) {
		return edgeTypes.contains(edgeType);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((description == null) ? 0 : description.hashCode());
		result = prime * result + ((edgeTypes == null) ? 0 : edgeTypes.hashCode());
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		result = prime * result + ((vertexTypes == null) ? 0 : vertexTypes.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		GraphType other = (GraphType) obj;

		if (!name.equals(other.name)) {
			return false;
		}
		if (!description.equals(other.description)) {
			return false;
		}
		if (!edgeTypes.equals(other.edgeTypes)) {
			return false;
		}
		if (!vertexTypes.equals(other.vertexTypes)) {
			return false;
		}
		return true;
	}

	public String getOptionsName() {
		return getName() + " Graph Type";
	}

}
