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

import java.util.List;

import org.jgrapht.Graph;

import ghidra.framework.plugintool.PluginTool;
import ghidra.service.graph.*;
import ghidra.util.Swing;
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

	private PluginTool pluginTool;
	private String description;

	/**
	 * Create the initial display, the graph-less visualization viewer, and its controls
	 * @param programGraphDisplayProvider provides a {@link PluginTool} for Docking features
	 */
	ExportAttributedGraphDisplay(ExportAttributedGraphDisplayProvider programGraphDisplayProvider) {
		this.pluginTool = programGraphDisplayProvider.getPluginTool();
	}

	@Override
	public void close() {
		// This display is not interactive, so N/A
	}

	@Override
	public void setGraphDisplayListener(GraphDisplayListener listener) {
		// This display is not interactive, so N/A
	}

	@Override
	public void selectVertices(List<String> vertexList) {
		// This display is not interactive, so N/A
	}

	@Override
	public void setLocation(String vertexID) {
		// This display is not interactive, so N/A
	}

	/**
	 * set the {@link AttributedGraph} for visualization
	 * @param attributedGraph the {@link AttributedGraph} to visualize
	 */
	private void doSetGraphData(AttributedGraph attributedGraph) {
		GraphExporterDialog dialog = new GraphExporterDialog(attributedGraph);
		Swing.runLater(() -> pluginTool.showDialog(dialog));
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
	public void setVertexLabel(String attributeName, int alignment, int size, boolean monospace,
			int maxLines) {
		// no effect
	}

	@Override
	public void setGraph(AttributedGraph graphData, String description, boolean append,
			TaskMonitor monitor) {
		this.description = description;
		doSetGraphData(graphData);
	}

	/**
	 * remove all vertices and edges from the {@link Graph}
	 */
	@Override
	public void clear() {
		// not interactive, so N/A
	}

	@Override
	public void updateVertexName(String id, String newName) {
		// do nothing
	}

	@Override
	public String getGraphDescription() {
		return description;
	}

}
