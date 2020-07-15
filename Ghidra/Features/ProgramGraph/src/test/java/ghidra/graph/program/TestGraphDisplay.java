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

import java.util.*;

import ghidra.service.graph.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class TestGraphDisplay implements GraphDisplay {
	private Set<String> definedVertexAttributes = new HashSet<>();
	private Set<String> definedEdgeAttributes = new HashSet<>();
	private String vertexAttributeName;
	private AttributedGraph graph;
	private String graphDescription;
	private GraphDisplayListener listener;
	private String currentFocusedVertex;
	private List<String> currentSelection;

	@Override
	public void setGraphDisplayListener(GraphDisplayListener listener) {
		this.listener = listener;
	}

	@Override
	public void setLocation(String vertexID) {
		currentFocusedVertex = vertexID;
	}

	public String getFocusedVertex() {
		return currentFocusedVertex;
	}

	@Override
	public void selectVertices(List<String> vertexList) {
		currentSelection = vertexList;
	}

	public List<String> getSelectedVertices() {
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
		vertexAttributeName = attributeName;
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
	public void updateVertexName(String id, String newName) {
		// nothing
	}

	@Override
	public String getGraphDescription() {
		return graphDescription;
	}

	public AttributedGraph getGraph() {
		return graph;
	}

	public void focusChanged(String vertexId) {
		listener.locationChanged(vertexId);
	}

	public void selectionChanged(List<String> vertexIds) {
		listener.selectionChanged(vertexIds);
	}
}
