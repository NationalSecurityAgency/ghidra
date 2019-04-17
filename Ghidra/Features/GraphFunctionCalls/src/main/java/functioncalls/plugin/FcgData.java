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
package functioncalls.plugin;

import functioncalls.graph.*;
import ghidra.graph.viewer.GraphPerspectiveInfo;
import ghidra.program.model.listing.Function;

/**
 * This class allows clients to retrieve and work on the graph and its related data.  Also, 
 * this class makes caching the data herein simple.
 */
interface FcgData {

	/**
	 * The function of this data
	 * @return the function
	 */
	Function getFunction();

	/**
	 * The graph of this data
	 * 
	 * @return the graph
	 */
	FunctionCallGraph getGraph();

	/**
	 * Returns the cache of {@link Function} edges.  These edges are not in the graph, but 
	 * rather are simple edges that represent a link between two functions.  This is used to 
	 * track existing edges that are not yet in the graph, which may be added later as the
	 * relevant nodes are inserted into the graph.
	 * 
	 * @return the cache
	 */
	FunctionEdgeCache getFunctionEdgeCache();

	/**
	 * True if this data has a valid function
	 * @return true if this data has a valid function
	 */
	boolean hasResults();

	/**
	 * False if the graph in this data has not yet been loaded
	 * @return false if the graph in this data has not yet been loaded
	 */
	boolean isInitialized();

	/**
	 * Dispose the contents of this data
	 */
	void dispose();

	/**
	 * Returns the view's graph perspective.  This is used by the view to restore itself.
	 * @return the view's graph perspective
	 */
	GraphPerspectiveInfo<FcgVertex, FcgEdge> getGraphPerspective();

	/**
	 * Sets the view information for this graph data.  This will be later used by the view
	 * to restore itself.
	 * 
	 * @param info the perspective
	 */
	void setGraphPerspective(GraphPerspectiveInfo<FcgVertex, FcgEdge> info);

	/**
	 * Returns true if this data's function is equal to the given function
	 *  
	 * @param f the function to test
	 * @return true if this data's function is equal to the given function
	 */
	boolean isFunction(Function f);
}
