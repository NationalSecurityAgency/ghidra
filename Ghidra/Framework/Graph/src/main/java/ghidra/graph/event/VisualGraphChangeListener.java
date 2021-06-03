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
package ghidra.graph.event;

/**
 * A listener to get notified of graph changes.
 */
public interface VisualGraphChangeListener<V, E> {

	/**
	 * Called when the given vertices have been added from the graph
	 * 
	 * @param vertices the added vertices
	 */
	public void verticesAdded(Iterable<V> vertices);

	/**
	 * Called when the given vertices have been removed from the graph
	 * 
	 * @param vertices the removed vertices
	 */
	public void verticesRemoved(Iterable<V> vertices);

	/**
	 * Called when the given edges have been added from the graph
	 * 
	 * @param edges the added edges
	 */
	public void edgesAdded(Iterable<E> edges);

	/**
	 * Called when the given edges have been removed from the graph
	 * 
	 * @param edges the removed edges
	 */
	public void edgesRemoved(Iterable<E> edges);
}
