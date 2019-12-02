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

import java.awt.Component;
import java.awt.geom.Point2D;

import javax.swing.JComponent;

import ghidra.graph.GVertex;

/**
 * A vertex that contains properties and state related to a user interface.
 * 
 * <P><U>equals() and hashCode()</U> - The graph API allows for cloning of layouts.  For this 
 * to correctly copy layout locations, each edge must override <code>equals</code> and
 * <code>hashCode</code> in order to properly find edges across graphs.
 */
public interface VisualVertex extends GVertex {

	/**
	 * Returns the component of this vertex.  This is used for rendering and interaction 
	 * with the user.
	 * 
	 * @return the component of this vertex
	 */
	public JComponent getComponent();

	/**
	 * Sets this vertex to be focused.   This differs from being selected in that multiple
	 * vertices in a graph can be selected, but only one can be the focused vertex.
	 * 
	 * @param focused true to focus; false to be marked as not focused
	 */
	public void setFocused(boolean focused);

	/**
	 * Returns true if this vertex is focused (see {@link #setFocused(boolean)}
	 * @return true if focused
	 */
	public boolean isFocused();

	/**
	 * Sets this vertex selected
	 * 
	 * @param selected true to select this vertex; false to de-select this vertex
	 */
	public void setSelected(boolean selected);

	/**
	 * Returns true if this vertex is selected
	 * 
	 * @return true if this vertex is selected 
	 */
	public boolean isSelected();

	/**
	 * Sets this vertex to be hovered
	 * 
	 * @param hovered true to be marked as hovered; false to be marked as not hovered
	 */
	public void setHovered(boolean hovered);

	/**
	 * Returns true if this vertex is being hovered by the mouse
	 * 
	 * @return true if this vertex is being hovered by the mouse
	 */
	public boolean isHovered();

	/**
	 * Sets the location of this vertex in the view
	 * 
	 * @param p the location of this vertex in the view
	 */
	public void setLocation(Point2D p);

	/**
	 * Returns the location of this vertex in the view
	 * 
	 * @return the location of this vertex in the view
	 */
	public Point2D getLocation();

	/**
	 * Returns true if the given component of this vertex is grabbable, which means that 
	 * mouse drags on that component will move the vertex.   
	 * 
	 * <P>This is used to differentiate components within a vertex that should receive mouse 
	 * events versus those components that will not be given mouse events.
	 * 
	 * @param c the component
	 * @return true if the component is grabbable
	 */
	public boolean isGrabbable(Component c);

	/**
	 * A dispose method that should be called when a vertex is reclaimed, never again to be 
	 * used in a graph or display
	 */
	public void dispose();

//==================================================================================================
// Rendering Methods (these could be refactored into another object in the future)
//==================================================================================================

	/**
	 * Sets the emphasis value for this vertex.  A value of 0 indicates no emphasis.
	 * 
	 * @param emphasisLevel the emphasis
	 */
	public void setEmphasis(double emphasisLevel);

	/**
	 * Returns the emphasis value of this vertex.  0 if not emphasized.
	 * 
	 * @return the emphasis value of this vertex.
	 */
	public double getEmphasis();

	/**
	 * Set the alpha, which determines how much of the vertex is visible/see through.  0 is 
	 * completely transparent.  This attribute allows transitional for animations.
	 * 
	 * @param alpha the alpha value
	 */
	public void setAlpha(double alpha);

	/**
	* Get the alpha, which determines how much of the vertex is visible/see through.  0 is 
	* completely transparent.  This attribute allows transitional for animations.
	* 
	* @return the alpha value
	*/
	public double getAlpha();

}
