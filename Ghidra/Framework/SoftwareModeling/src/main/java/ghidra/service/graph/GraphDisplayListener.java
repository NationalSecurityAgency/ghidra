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

/**
 * Interface for being notified when the user interacts with a visual graph display
 */
public interface GraphDisplayListener {
	/**
	 * Notification that the graph window has been closed
	 */
	public void graphClosed();

	/**
	 * Notification that the set of selected vertices has changed
	 * 
	 * @param vertices the set of currently selected vertices
	 */
	public void selectionChanged(Set<AttributedVertex> vertices);

	/**
	 * Notification that the "focused" (active) vertex has changed
	 * @param vertex the vertex that is currently "focused"
	 */
	public void locationFocusChanged(AttributedVertex vertex);

	/**
	 * Makes a new GraphDisplayListener of the same type as the specific
	 * instance of this GraphDisplayListener
	 * 
	 * @param graphDisplay the new {@link GraphDisplay} the new listener will support
	 * @return A new instance of a GraphDisplayListener that is the same type as as the instance
	 * on which it is called
	 */
	public GraphDisplayListener cloneWith(GraphDisplay graphDisplay);

	/**
	 * Tells the listener that it is no longer needed and it can release any listeners/resources
	 */
	public void dispose();

}
