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
package ghidra.graph.graphs;

import ghidra.graph.viewer.vertex.AbstractVisualVertex;

/**
 * A vertex used for testing.
 */
public abstract class AbstractTestVertex extends AbstractVisualVertex {

	private volatile boolean hasBeenEmphasised;
	private String name;

	protected AbstractTestVertex(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

	@Override
	public void setEmphasis(double emphasisLevel) {
		super.setEmphasis(emphasisLevel);
		hasBeenEmphasised |= (Double.compare(0, emphasisLevel) < 0);
	}

	public boolean hasBeenEmphasised() {
		return hasBeenEmphasised;
	}

	@Override
	public void dispose() {
		// subclasses may override
	}

	@Override
	public String toString() {
		return name;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((name == null) ? 0 : name.hashCode());
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
		AbstractTestVertex other = (AbstractTestVertex) obj;
		if (name == null) {
			if (other.name != null) {
				return false;
			}
		}
		else if (!name.equals(other.name)) {
			return false;
		}
		return true;
	}

}
