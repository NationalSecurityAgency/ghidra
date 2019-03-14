/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.model.graph;

import java.util.Iterator;


/**
 * Collection of edges and vertices that make up a graph.
 * <code>GraphData</code> is intended to be displayed on a <code>GraphDisplay</code>.
 */
public interface GraphData {
    /**
     * Create a Vertex with a given name and vertex ID.
     * The vertexID string is used to uniquely identify a vertex.  It is
     * used for selection and location mapping from/to Ghidra and the graph
     * display.  It should be mappable back to an location/selection that represents
     * the vertex in ghidra terms.
     * 
     * @param name name of the vertex, its label
     * @param vertexID identifier to uniquely identify this vertex.
     *
     * @return a graph vertex
     */
    public GraphVertex createVertex(String name, String vertexID);

    /**
     * Get a vertex with a given address string.
     *
     * @param vertexID identifier to uniquely identify this vertex.  The key is
     *         useful for mapping location/selection from/to Ghidra and Renoir
     *
     * @return a vertex tagged with the given address.
     */
    public GraphVertex getVertex(String vertexID);

    /**
     * Create an edge on the graph connecting two vertices.
     *  NOTE: These MUST be two vertices created from the above createVertex function.
     *
     * The address string is used to uniquely identify a vertex.  It is
     * used for selection and location mapping from/to Ghidra and the graph
     * display.  It should be mappable back to an actual address in ghidra
     * terms.
     *
     * @param vertexID identifier to uniquely identify this vertex
     * @param start start vertex
     * @param end end vertex
     *
     * @return a graph edge
     */
    public GraphEdge createEdge(String vertexID, GraphVertex start, GraphVertex end);

    /**
     * Get an iterator over all defined vertices.  Every object in the iterator
     * will be a GraphVertex.
     *
     * @return a vertex iterator
     */
    public Iterator<? extends GraphVertex> getVertices();

    /**
     * Get an iterator over all defined edges.  Every object in the iterator
     * will be a GraphEdge.
     */
    public Iterator<? extends GraphEdge> getEdges();
}
