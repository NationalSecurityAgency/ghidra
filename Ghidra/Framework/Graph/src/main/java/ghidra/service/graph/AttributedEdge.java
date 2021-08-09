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

/**
 * Generic directed graph edge implementation
 */
public class AttributedEdge extends Attributed {
	public static final String EDGE_TYPE_KEY = "EdgeType";
	private final String id;

	/**
	 * Constructs a new GhidraEdge
	 * @param id the unique id for the edge
	 */
	public AttributedEdge(String id) {
		this.id = id;
	}

	@Override
	public String toString() {
		return id;
	}

	/**
	 * Returns the id for this edge
	 * @return the id for this edge
	 */
	public String getId() {
		return id;
	}

	@Override
	public int hashCode() {
		return id.hashCode();
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
		AttributedEdge other = (AttributedEdge) obj;
		return id.equals(other.id);
	}

	/**
	 * Returns the edge type for this edge
	 * @return the edge type for this edge
	 */
	public String getEdgeType() {
		return getAttribute(EDGE_TYPE_KEY);
	}

	/**
	 * Sets the edge type for this edge. Should be a value defined by the {@link GraphType} for
	 * this graph, but there is no enforcement for this. If the value is not defined in GraphType,
	 * it will be rendered using the default edge color for {@link GraphType}
	 * @param edgeType the edge type for this edge
	 */
	public void setEdgeType(String edgeType) {
		setAttribute(EDGE_TYPE_KEY, edgeType);
	}
}
