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
package ghidra.graph.program;

import java.util.HashSet;
import java.util.Set;

import docking.action.DockingAction;
import docking.widgets.EventTrigger;
import ghidra.service.graph.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class TestGraphDisplay implements GraphDisplay {
	private Set<String> definedVertexAttributes = new HashSet<>();
	private Set<String> definedEdgeAttributes = new HashSet<>();
	private AttributedGraph graph;
	private String graphDescription;
	private GraphDisplayListener listener;
	private AttributedVertex focusedVertex;
	private Set<AttributedVertex> currentSelection;

	@Override
	public void setGraphDisplayListener(GraphDisplayListener listener) {
		this.listener = listener;
	}

	@Override
	public void setFocusedVertex(AttributedVertex vertex, EventTrigger eventTrigger) {
		focusedVertex = vertex;
	}

	@Override
	public AttributedVertex getFocusedVertex() {
		return focusedVertex;
	}

	@Override
	public void selectVertices(Set<AttributedVertex> vertexList, EventTrigger eventTrigger) {
		currentSelection = vertexList;
	}

	@Override
	public Set<AttributedVertex> getSelectedVertices() {
		return currentSelection;
	}

	@Override
	public void close() {
		// nothing
	}

	@Override
	public void defineVertexAttribute(String name) {
		definedVertexAttributes.add(name);
	}

	@Override
	public void defineEdgeAttribute(String name) {
		definedEdgeAttributes.add(name);
	}

	@Override
	public void setVertexLabel(String attributeName, int alignment, int size, boolean monospace,
			int maxLines) {
		//  nothing
	}

	@Override
	public void setGraph(AttributedGraph graph, String description, boolean append,
			TaskMonitor monitor)
			throws CancelledException {
		this.graph = graph;
		this.graphDescription = description;
	}

	@Override
	public void clear() {
		// nothing
	}

	@Override
	public void updateVertexName(AttributedVertex vertex, String newName) {
		// nothing
	}

	@Override
	public String getGraphDescription() {
		return graphDescription;
	}

	@Override
	public AttributedGraph getGraph() {
		return graph;
	}

	public void focusChanged(AttributedVertex vertex) {
		listener.locationFocusChanged(vertex);
	}

	public void selectionChanged(Set<AttributedVertex> vertices) {
		listener.selectionChanged(vertices);
	}

	@Override
	public void addAction(DockingAction action) {
		// do nothing, actions are not supported by this display
	}

}
