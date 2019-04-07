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
package ghidra.graph.viewer.vertex;

import java.awt.Shape;

/**
 * An interface that can be implemented to provide vertex shapes to the UI.  These are used
 * for rendering and mouse interaction.  Typically, these shapes are the same.   Clients that
 * wish to allow for complicated shapes can use this interface to control mouse hit detection
 * while providing simpler shape painting.
 * 
 * <p>The only time a client would need this separation of shapes is if they create complex 
 * renderings with odd shapes (a shape that is not a rectangle).   With such a complex 
 * shape, those graph views that paint only shapes, like the satellite viewer, will look 
 * peculiar.  
 */
public interface VertexShapeProvider {

	/**
	 * Returns the compact shape that the user will see when full, detailed rendering is 
	 * not being performed for a vertex, such as in the satellite viewer or when fully-zoomed-out
	 * 
	 * @return the shape
	 */
	public Shape getCompactShape();

	/**
	 * Returns the full (the actual) shape of a vertex.  This can be used to determine if a 
	 * mouse point intersects a vertex or to get the real bounding-box of a vertex.
	 * 
	 * @return the shape
	 */
	default public Shape getFullShape() {
		return getCompactShape();
	}
}
