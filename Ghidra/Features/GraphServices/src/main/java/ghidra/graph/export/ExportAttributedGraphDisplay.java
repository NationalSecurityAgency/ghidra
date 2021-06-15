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
package ghidra.graph.export;

import java.util.*;

import org.jgrapht.Graph;

import docking.action.DockingActionIf;
import docking.widgets.EventTrigger;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.service.graph.*;
import ghidra.util.task.TaskMonitor;

/**
 * {@link GraphDisplay} implementation for exporting graphs.  In this case, there is no
 * associated visual display, instead the graph output gets sent to a file.  The 
 * {@link GraphDisplay} is mostly just a placeholder for executing the export function.  By
 * hijacking the {@link GraphDisplayProvider} and {@link GraphDisplay} interfaces for exporting,
 * all graph generating operations can be exported instead of being displayed without changing
 * the graph generation code.    
 */
class ExportAttributedGraphDisplay implements GraphDisplay {

	private final PluginTool tool;
	private String title;
	private AttributedGraph graph;

	/**
	 * Create the initial display, the graph-less visualization viewer, and its controls
	 * @param programGraphDisplayProvider provides a {@link PluginTool} for Docking features
	 */
	ExportAttributedGraphDisplay(ExportAttributedGraphDisplayProvider programGraphDisplayProvider) {
		this.tool = programGraphDisplayProvider.getPluginTool();
	}

	@Override
	public void close() {
		// This display is not interactive, so N/A
	}

	@Override
	public void setGraphDisplayListener(GraphDisplayListener listener) {
		// This display is not interactive, so just dispose the listener
		listener.dispose();
	}

	/**
	 * set the {@link AttributedGraph} for visualization
	 * @param attributedGraph the {@link AttributedGraph} to visualize
	 */
	private void doSetGraphData(AttributedGraph attributedGraph) {
		List<AttributedGraphExporter> exporters = findGraphExporters();
		GraphExporterDialog dialog = new GraphExporterDialog(attributedGraph, exporters);
		tool.showDialog(dialog);
	}

	private List<AttributedGraphExporter> findGraphExporters() {
		GraphDisplayBroker service = tool.getService(GraphDisplayBroker.class);
		if (service != null) {
			return service.getGraphExporters();
		}
		return Collections.emptyList();
	}

	@Override
	public void defineVertexAttribute(String attributeName) {
		// no effect
	}

	@Override
	public void defineEdgeAttribute(String attributeName) {
		// no effect
	}

	@Override
	public void setVertexLabelAttribute(String attributeName, int alignment, int size,
			boolean monospace,
			int maxLines) {
		// no effect
	}

	@Override
	public void setGraph(AttributedGraph graph, String title, boolean append,
			TaskMonitor monitor) {
		this.title = title;
		this.graph = graph;
		doSetGraphData(graph);
	}

	/**
	 * remove all vertices and edges from the {@link Graph}
	 */
	@Override
	public void clear() {
		// not interactive, so N/A
	}

	@Override
	public void updateVertexName(AttributedVertex vertex, String newName) {
		// do nothing
	}

	@Override
	public String getGraphTitle() {
		return title;
	}

	@Override
	public void addAction(DockingActionIf action) {
		// do nothing, actions are not supported by this display
	}

	@Override
	public AttributedVertex getFocusedVertex() {
		return null;
	}

	@Override
	public Set<AttributedVertex> getSelectedVertices() {
		return Collections.emptySet();
	}

	@Override
	public void setFocusedVertex(AttributedVertex vertex, EventTrigger eventTrigger) {
		// not interactive, so N/A
	}

	@Override
	public AttributedGraph getGraph() {
		return graph;
	}

	@Override
	public void selectVertices(Set<AttributedVertex> vertexList, EventTrigger eventTrigger) {
		// not interactive, so N/A
	}

}
