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
 * Graph vertex with attributes
 */
public class AttributedVertex extends Attributed {

	private final String id;

	/**
	 * Constructs a new GhidraVertex with the given id and name
	 * 
	 * @param id the unique id for the vertex
	 * @param name the name for the vertex
	 */
	public AttributedVertex(String id, String name) {
		this.id = id;
		setName(name);
	}

	public AttributedVertex(String id) {
		this(id, id);
	}

	/**
	 * Sets the name on the vertex
	 * 
	 * @param name the new name for the vertex
	 */
	public void setName(String name) {
		setAttribute("Name", name);
	}

	/**
	 * Returns the id for this vertex
	 * @return the id for this vertex
	 */
	public String getId() {
		return id;
	}

	/**
	 * returns the name of the vertex
	 * 
	 * @return  the name of the vertex
	 */
	public String getName() {
		return getAttribute("Name");
	}

	@Override
	public String toString() {
		return getName() + " (" + id + ")";
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
		AttributedVertex other = (AttributedVertex) obj;
		return id.equals(other.id);
	}

}
