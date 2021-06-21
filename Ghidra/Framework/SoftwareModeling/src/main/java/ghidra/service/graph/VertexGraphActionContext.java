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

import java.util.Objects;
import java.util.Set;

import docking.ComponentProvider;

/**
 * GraphActionContext for when user invokes a popup action on a graph vertex.
 */
public class VertexGraphActionContext extends GraphActionContext {

	private AttributedVertex clickedVertex;

	public VertexGraphActionContext(ComponentProvider componentProvider,
			AttributedGraph graph, Set<AttributedVertex> selectedVertices,
			AttributedVertex locatedVertex, AttributedVertex clickedVertex) {

		super(componentProvider, graph, selectedVertices, locatedVertex);
		this.clickedVertex = Objects.requireNonNull(clickedVertex);
	}

	/**
	 * Returns the vertex from where the popup menu was launched
	 * @return  the vertex from where the popup menu was launched
	 */
	public AttributedVertex getClickedVertex() {
		return clickedVertex;
	}

}
