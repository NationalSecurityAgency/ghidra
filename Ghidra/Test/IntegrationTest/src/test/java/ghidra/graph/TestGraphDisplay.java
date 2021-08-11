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
package ghidra.graph;

import java.util.Map;
import java.util.Set;

import docking.action.DockingActionIf;
import docking.widgets.EventTrigger;
import ghidra.service.graph.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class TestGraphDisplay implements GraphDisplay {
	private AttributedGraph graph;
	private String title;
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
	public void setGraph(AttributedGraph graph, String title, boolean append,
			TaskMonitor monitor)
			throws CancelledException {
		if (append) {
			this.graph = mergeGraphs(graph, this.graph);
		}
		else {
			this.graph = graph;
		}
		this.title = title;
	}

	@Override
	public void setGraph(AttributedGraph graph, GraphDisplayOptions options, String title,
			boolean append, TaskMonitor monitor) throws CancelledException {
		setGraph(graph, title, append, monitor);
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
	public String getGraphTitle() {
		return title;
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
	public void addAction(DockingActionIf action) {
		// do nothing, actions are not supported by this display
	}

	private AttributedGraph mergeGraphs(AttributedGraph newGraph, AttributedGraph oldGraph) {
		for (AttributedVertex vertex : oldGraph.vertexSet()) {
			newGraph.addVertex(vertex);
		}
		for (AttributedEdge edge : oldGraph.edgeSet()) {
			AttributedVertex from = oldGraph.getEdgeSource(edge);
			AttributedVertex to = oldGraph.getEdgeTarget(edge);
			AttributedEdge newEdge = newGraph.addEdge(from, to);
			Map<String, String> attributeMap = edge.getAttributes();
			for (String key : attributeMap.keySet()) {
				newEdge.setAttribute(key, edge.getAttribute(key));
			}
		}
		return newGraph;
	}
}
