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
/*
 * GraphDisplay.java
 *
 * Created on March 4, 2002, 3:42 PM
 */

package ghidra.program.model.graph;

import ghidra.util.exception.GraphException;

/**
 * Handle object to a graph display.
 */
public interface GraphDisplay {
	/**Aligns the graph text to the left*/
	public static final int ALIGN_LEFT = 0;
	/**Aligns the graph text to the center*/
	public static final int ALIGN_CENTER = 1;
	/**Aligns the graph text to the right*/
	public static final int ALIGN_RIGHT = 2;
    /**
     * Pop the graph display to the front.
     * @throws GraphException thrown if an error occurs while communicating with the graph service.
     */
    void popup() throws GraphException;
    /**
     * Clear the graph data in the graph display
     * @throws GraphException thrown if an error occurs while communicating with the graph service.
     */
    void clear() throws GraphException;
    /**
     * Close the graph.  This destroys the graph display.
     */
    void close();
    /**
     * Check if the graph display is still valid.
     */
    boolean isValid();
    /**
     * Set the graph data.  This will append the data to the graph.
     * Call the clear method if this data is to replace the exising
     * data on this display.
     *
     * @param graph the graph data to apply to the graph display.
     * @throws GraphException thrown if an error occurs while communicating with the graph service.
     */
    void setGraphData(GraphData graph) throws GraphException;
    /**
     * Define the name of an attribute on edges in the graph displayed.
     * @param attributeName the name of the attribute to define on an edge.
     * @throws GraphException thrown if an error occurs while communicating with the graph service.
     */
    void defineEdgeAttribute(String attributeName) throws GraphException;
    /**
     * Define the name of an attribute on vertices in the graph displayed.
     * @param attributeName the name of the attribute to define on a vertex.
     * @throws GraphException thrown if an error occurs while communicating with the graph service.
     */
    void defineVertexAttribute(String attributeName) throws GraphException;
    /**
     * Indicate that the specified vertex attribute should be displayed as the vertex label.
     * @param attributeName the name of the vertex attribute
     * @param alignment ALIGN_LEFT, ALIGN_CENTER or ALIGN_RIGHT
     * @param size font size (8, 10, 12, etc.)
     * @param monospace if true a monospace font will be used.
     * @param maxLines indicate the maximum number of lines to be displayed for the label.  A value &lt;= 1 will
     * result in a single line display and the preferred geometric shapes.  A value &gt;1 will force the use of
     * rectangualr nodes.
     * @throws GraphException thrown if an error occurs while communicating with the graph service.
     */
    void setVertexLabel(String attributeName, int alignment, int size, boolean monospace, int maxLines) throws GraphException;
    /**
     * Set the handler that will map addresses strings on vertices and edges
     * to/from objects that make sense to the generator of the graph.
     * @param handler the GraphSelectionHandler to set on this GraphDisplay.
     */ 
    void setSelectionHandler(GraphSelectionHandler handler);
    /**
     * Tell the display to set the selection set on the graph based on some
     * object that will be passed to the GraphSelectionHandler to map into
     * address strings.
     *
     * @param selectionObject opaque object to be passed to the selection handler.
     * @param global true if the selection is to be set on all known graph windows.
     */
    void select(Object selectionObject, boolean global);
    /**
     * Tell the display to set the location cursor on the graph based on some
     * object that will be passed to the GraphSelectionHandler to map into
     * and address string.
     *
     * @param locationObject opaque object to be passed to the selection handler.
     * @param global true if the selection is to be set on all known graph windows.
     */
    void locate(Object locationObject, boolean global);
}
