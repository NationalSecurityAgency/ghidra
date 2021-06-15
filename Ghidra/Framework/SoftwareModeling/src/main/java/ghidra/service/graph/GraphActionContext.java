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

import java.util.Set;

import docking.ActionContext;
import docking.ComponentProvider;

/**
 * The base ActionContext for the GraphDisplay instances.
 */
public class GraphActionContext extends ActionContext {
	private final AttributedGraph graph;
	private final Set<AttributedVertex> selectedVertices;
	private final AttributedVertex focusedVertex;

	public GraphActionContext(ComponentProvider componentProvider,
			AttributedGraph graph, Set<AttributedVertex> selectedVertices,
			AttributedVertex locatedVertex) {

		super(componentProvider);
		this.graph = graph;
		this.selectedVertices = selectedVertices;
		this.focusedVertex = locatedVertex;
	}

	/**
	 * Returns the graph
	 * @return the graph
	 */
	public AttributedGraph getGraph() {
		return graph;
	}

	/**
	 * Returns the set of selectedVertices in the graph
	 * @return the set of selectedVertices in the graph
	 */
	public Set<AttributedVertex> getSelectedVertices() {
		return selectedVertices;
	}

	/**
	 * Returns the focused vertex (similar concept to the cursor in a text document)
	 * @return the focused vertex
	 */
	public AttributedVertex getFocusedVertex() {
		return focusedVertex;
	}

}
