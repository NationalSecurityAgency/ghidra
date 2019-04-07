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
package ghidra.graph.viewer.layout;

import java.awt.geom.Point2D;

/**
 * A listener for layout changes.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public interface LayoutListener<V, E> {

	public enum ChangeType {
		USER,      		// real changes that should be tracked 
		TRANSIENT,  	// transient changes that can be ignored
		RESTORE			// changes that happen when re-serializing saved locations
	}

	/**
	 * Called when a vertex location has changed.
	 * 
	 * @param v the vertex
	 * @param point the new vertex location
	 * @param changeType the type of the change
	 */
	public void vertexLocationChanged(V v, Point2D point, ChangeType changeType);
}
