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
package ghidra.graph.viewer;

import ghidra.graph.viewer.edge.VisualGraphPathHighlighter;

/**
 * An enum that lists possible states for highlighting paths between vertices in a graph. 
 * 
 * @see VisualGraphPathHighlighter
 */
public enum PathHighlightMode {

	//@formatter:off
	 
	/** Shows all cycles in the graph */
	ALLCYCLE,
	
	/** Shows all cycles for a given vertex */
	CYCLE, 	 
	
	/** Shows all paths that can reach the given vertex */
	IN,
	
	/** Shows all paths coming into and out of a vertex */
	INOUT,
	
	/** Shows no paths */
	OFF,
	
	/** Shows all paths reachable from the current vertex */
	OUT, 	
	
	/** Shows all paths between two vertices */
	PATH,
	
	/** Shows all paths that must have been traveled to reach the current vertex */
	SCOPED_FORWARD,
	
	/** Shows all paths that will be traveled after leaving the current vertex */
	SCOPED_REVERSE;
	//@formatter:on
}
