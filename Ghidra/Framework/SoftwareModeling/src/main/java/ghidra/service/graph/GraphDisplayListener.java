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

/**
 * Interface for being notified when the user interacts with a visual graph display.
 */
public interface GraphDisplayListener {
	/**
	 * Notification that the graph window has been closed
	 */
	public void graphClosed();

	/**
	 * Notification that the list of selected vertices has changed
	 * 
	 * @param vertexIds the list of vertex ids for the currently selected vertices.
	 */
	public void selectionChanged(List<String> vertexIds);

	/**
	 * Notification that the "focused" (active) vertex has changed.
	 * @param vertexId the vertex id of the currently "focused" vertex
	 */
	public void locationChanged(String vertexId);
}
