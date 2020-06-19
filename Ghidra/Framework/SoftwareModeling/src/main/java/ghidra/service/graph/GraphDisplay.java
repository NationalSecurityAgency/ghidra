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

import java.util.List;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Interface for objects that display (or consume) graphs.  Normally, a graph display represents
 * a visual component for displaying and interacting with a graph.  Some implementation may not
 * be a visual component, but instead consumes/processes the graph (i.e. graph exporter). In this
 * case, there is no interactive element and once the graph has been set on the display, it is 
 * closed.
 */
public interface GraphDisplay {
	public static final int ALIGN_LEFT = 0;  // aligns graph text to the left
	public static final int ALIGN_CENTER = 1; // aligns graph text to the center
	public static final int ALIGN_RIGHT = 2; // aligns graph text to the right

	/**
	 * Sets a {@link GraphDisplayListener} to be notified when the user changes the vertex focus
	 * or selects one or more nodes in a graph window
	 * 
	 * @param listener the listener to be notified
	 */
	public void setGraphDisplayListener(GraphDisplayListener listener);

	/**
	 * Tells the graph display window to focus 
	 * 
	 * @param vertexID the id of the vertex to focus
	 */
	public void setLocation(String vertexID);

	/**
	 * Tells the graph display window to select the vertices with the given ids
	 * 
	 * @param vertexList the list of vertex ids to select
	 */
	public void selectVertices(List<String> vertexList);

	/**
	 * Closes this graph display window.
	 */
	public void close();

	/**
	 * Defines a vertex attribute type for this graph window
	 * 
	 * @param name the name of the attribute which may be attached to vertices.
	 */
	public void defineVertexAttribute(String name);

	/**
	 * Defines an edge attribute type for this graph window
	 * 
	 * @param name the name of the attribute which may be attached to edges.
	 */
	public void defineEdgeAttribute(String name);

	/**
	 * Sets the name of the attribute which should be used as the primary vertex label in the display.
	 * @param attributeName the name of the attribute to use as the display label for vertices.
	 * @param alignment (ALIGN_LEFT, ALIGN_RIGHT, or ALIGN_CENTER)
	 * @param size the font size to use for the display label
	 * @param monospace true if the font should be monospaced
	 * @param maxLines the maximum number lines to display in the vertex labels
	 */
	public void setVertexLabel(String attributeName, int alignment, int size, boolean monospace,
			int maxLines);

	/**
	 * Sets the graph to be displayed or consumed by this graph display
	 * @param graph the graph to display or consume
	 * @param description a description of the graph
	 * @param monitor a {@link TaskMonitor} which can be used to cancel the graphing operation
	 * @param append if true, append the new graph to any existing graph.
	 * @throws CancelledException thrown if the graphing operation was cancelled
	 */
	public void setGraph(AttributedGraph graph, String description, boolean append,
			TaskMonitor monitor)
			throws CancelledException;

	/**
	 * Clears all graph vertices and edges from this graph display
	 */
	public void clear();

	/**
	 * Updates a vertex to a new name
	 * @param id the vertix id
	 * @param newName the new name of the vertex
	 */
	public void updateVertexName(String id, String newName);

	/**
	 * Returns the description of the current graph
	 * @return the description of the current graph
	 */
	public String getGraphDescription();
}
