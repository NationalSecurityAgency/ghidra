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

import docking.action.DockingActionIf;
import docking.widgets.EventTrigger;
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
	 * values are color names or rgb in hex '0xFF0000' is red
	 */
	String SELECTED_VERTEX_COLOR = "selectedVertexColor";
	/**
	 * values are color names or rgb in hex '0xFF0000' is red
	 */
	String SELECTED_EDGE_COLOR = "selectedEdgeColor";
	/**
	 * values are defined as String symbols in LayoutFunction class
	 *
	 * KAMADA_KAWAI,FRUCTERMAN_REINGOLD,CIRCLE_MINCROSS,TIDIER_TREE,TIDIER_RADIAL_TREE,
	 * MIN_CROSS_TOP_DOWN,MIN_CROSS_LONGEST_PATH,MIN_CROSS_NETWORK_SIMPLEX,MIN_CROSS_COFFMAN_GRAHAM,
	 * EXP_MIN_CROSS_TOP_DOWN,EXP_MIN_CROSS_LONGEST_PATH,EXP_MIN_CROSS_NETWORK_SIMPLEX,
	 * EXP_MIN_CROSS_COFFMAN_GRAHAM,TREE,RADIAL,BALLOON,GEM
	 *
	 * may have no meaning for a different graph visualization library
	 */
	String INITIAL_LAYOUT_ALGORITHM = "initialLayoutAlgorithm";
	/**
	 * true or false
	 * may have no meaning for a different graph visualization library
	 */
	String DISPLAY_VERTICES_AS_ICONS = "displayVerticesAsIcons";
	/**
	 * values are the strings N,NE,E,SE,S,SW,W,NW,AUTO,CNTR
	 * may have no meaning for a different graph visualization library
	 */
	String VERTEX_LABEL_POSITION = "vertexLabelPosition";
	/**
	 * true or false, whether edge selection via a mouse click is enabled.
	 * May not be supported by another graph visualization library
	 */
	String ENABLE_EDGE_SELECTION = "enableEdgeSelection";
	/**
	 * a comma-separated list of edge type names in priority order
	 */
	String EDGE_TYPE_PRIORITY_LIST = "edgeTypePriorityList";
	/**
	 * a comma-separated list of edge type names.
	 * any will be considered a favored edge for the min-cross layout
	 * algorithms.
	 * May have no meaning with a different graph visualization library
	 */
	String FAVORED_EDGES = "favoredEdges";

	/**
	 * Sets a {@link GraphDisplayListener} to be notified when the user changes the vertex focus
	 * or selects one or more nodes in a graph window
	 * 
	 * @param listener the listener to be notified
	 */
	public void setGraphDisplayListener(GraphDisplayListener listener);

	/**
	 * Tells the graph display window to focus the vertex with the given id
	 * 
	 * @param vertex the vertex to focus
	 * @param eventTrigger Provides a hint to the GraphDisplay as to why we are updating the
	 * graph location so that the GraphDisplay can decide if it should send out a notification via
	 * the {@link GraphDisplayListener#locationFocusChanged(AttributedVertex)}. For example, if we
	 * are updating the the location due to an event from the main application, we don't want to
	 * notify the application the graph changed to avoid event cycles. See {@link EventTrigger} for
	 * more information.
	 */
	public void setFocusedVertex(AttributedVertex vertex, EventTrigger eventTrigger);

	/**
	 * Returns the graph for this display
	 * @return the graph for this display
	 */
	public AttributedGraph getGraph();

	/**
	 * Returns the currently focused vertex or null if no vertex is focused
	 * 
	 * @return  the currently focused vertex or null if no vertex is focused
	 */
	public AttributedVertex getFocusedVertex();

	/**
	 * Tells the graph display window to select the vertices with the given ids
	 * 
	 * @param vertexSet the set of vertices to select
	 * @param eventTrigger Provides a hint to the GraphDisplay as to why we are updating the
	 * graph location so that the GraphDisplay can decide if it should send out a notification via
	 * the {@link GraphDisplayListener#selectionChanged(Set)}. For example, if we are updating
	 * the the location due to an event from the main application, we don't want to notify the 
	 * application the graph changed to avoid event cycles. See {@link EventTrigger} for more
	 * information.
	 */
	public void selectVertices(Set<AttributedVertex> vertexSet, EventTrigger eventTrigger);

	/**
	 * Returns a set of vertex ids for all the currently selected vertices
	 * 
	 * @return  a set of vertex ids for all the currently selected vertices
	 */
	public Set<AttributedVertex> getSelectedVertices();

	/**
	 * Closes this graph display window.
	 */
	public void close();

	/**
	 * Sets the graph to be displayed or consumed by this graph display
	 * 
	 * @param graph the graph to display or consume
	 * @param title a title for the graph
	 * @param monitor a {@link TaskMonitor} which can be used to cancel the graphing operation
	 * @param append if true, append the new graph to any existing graph
	 * @throws CancelledException thrown if the graphing operation was cancelled
	 * @deprecated You should now use the form that takes in a {@link GraphDisplayOptions}
	 */
	public default void setGraph(AttributedGraph graph, String title, boolean append,
			TaskMonitor monitor) throws CancelledException {
		setGraph(graph, new GraphDisplayOptions(graph.getGraphType()), title, append, monitor);
	}
	/**
	 * Sets the graph to be displayed or consumed by this graph display
	 * 
	 * @param graph the graph to display or consume
	 * @param options {@link GraphDisplayOptions} for configuring how the display will
	 * render vertices and edges based on there vertex type and edge type respectively.
	 * @param title a title for the graph
	 * @param monitor a {@link TaskMonitor} which can be used to cancel the graphing operation
	 * @param append if true, append the new graph to any existing graph
	 * @throws CancelledException thrown if the graphing operation was cancelled
	 */
	public void setGraph(AttributedGraph graph, GraphDisplayOptions options, String title,
			boolean append, TaskMonitor monitor) throws CancelledException;

	/**
	 * Clears all graph vertices and edges from this graph display
	 */
	public void clear();

	/**
	 * Updates a vertex to a new name
	 * 
	 * @param vertex the vertex to rename
	 * @param newName the new name for the vertex
	 */
	public void updateVertexName(AttributedVertex vertex, String newName);

	/**
	 * Returns the title of the current graph
	 * 
	 * @return the title of the current graph
	 */
	public String getGraphTitle();

	/**
	 * Adds the action to the graph display. Not all GraphDisplays support adding custom
	 * actions, so this may have no effect.
	 * 
	 * @param action the action to add
	 */
	public void addAction(DockingActionIf action);
}
