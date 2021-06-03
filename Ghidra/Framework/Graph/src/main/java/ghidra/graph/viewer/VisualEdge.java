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

import java.awt.geom.Point2D;
import java.util.List;

import ghidra.graph.GEdge;

/**
 * An edge that contains properties and state related to a user interface.
 * 
 * <P>An edge can be selected, which means that it has been clicked by the user.  Also, an 
 * edge can be part of an active path.  This allows the UI to paint the edge differently if it
 * is in the active path.   The active path concept applies to both hovered and focused vertices
 * separately.  A hovered vertex is one that the user moves the mouse over; a focused vertex is
 * one that is selected.
 * 
 * <a id="articulations"></A>
 * <P><U>Articulations</U> - The start and end points are always part of the
 * edge.  Any additional points on the edge are considered articulation points.  Thus, an edge
 * without articulations will be drawn as a straight line.  An edge with articulations will
 * be drawn as a series of straight lines from point-to-point, allowing the layout algorithm
 * to add points to the edge to avoid line crossings; these points are used to make the 
 * drawing of the edge cleaner.
 *
 * <P><U>equals() and hashCode()</U> - The graph API allows for cloning of layouts.  For this 
 * to correctly copy layout locations, each edge must override <code>equals</code> and
 * <code>hashCode</code> in order to properly find edges across graphs.
 *
 * @param <V> the vertex type
 */
public interface VisualEdge<V extends VisualVertex> extends GEdge<V> {

	/**
	 * Sets this edge selected.  This is usually in response to the user selecting the edge.
	 * 
	 * @param selected true to select this edge; false to de-select this vertex
	 */
	public void setSelected(boolean selected);

	/**
	 * Returns true if this edge is selected
	 * 
	 * @return true if this edge is selected 
	 */
	public boolean isSelected();

	/**
	 * Sets this edge to be marked as in the active path of a currently hovered vertex
	 * 
	 * @param inPath true to be marked as in the active path; false to be marked as not 
	 *        in the active path
	 */
	public void setInHoveredVertexPath(boolean inPath);

	/**
	 * Returns true if this edge is part of an active path for a currently hovered 
	 * vertex (this allows the edge to be differently rendered)
	 * 
	 * @return true if this edge is part of the active path
	 */
	public boolean isInHoveredVertexPath();

	/**
	 * Sets this edge to be marked as in the active path of a currently focused/selected vertex
	 * 
	 * @param inPath true to be marked as in the active path; false to be marked as not 
	 *        in the active path
	 */
	public void setInFocusedVertexPath(boolean inPath);

	/**
	 * Returns true if this edge is part of an active path for a currently focused/selected 
	 * vertex (this allows the edge to be differently rendered)
	 * 
	 * @return true if this edge is part of the active path
	 */
	public boolean isInFocusedVertexPath();

	/**
	 * Returns the points (in {@link GraphViewerUtils} View Space) of the articulation
	 * 
	 * <P><A HREF="#articulations">What are articulations?</A>
	 * 
	 * @return the points (in View Space space) of the articulation.
	 */
	public List<Point2D> getArticulationPoints();

	/**
	 * Sets the articulation points for the given edge
	 * 
	 * <P><A HREF="#articulations">What are articulations?</A>
	 * 
	 * @param points the points
	 */
	public void setArticulationPoints(List<Point2D> points);

	/**
	 * Creates a new edge of this type using the given vertices.
	 * 
	 * <P>Implementation Note: the odd type 'E' below is there so that subclasses can return
	 * the type of their implementation.   Basically, the decision was made to have each subclass
	 * suppress the warning that appears, since they know the type is safe.  Alternatively, 
	 * each client would have to cast the return type, which seems less desirable.
	 * 
	 * @param start the start vertex
	 * @param end the end vertex
	 * @return the new edge
	 */
	public <E extends VisualEdge<V>> E cloneEdge(V start, V end);

//==================================================================================================
// Rendering Methods (these could be refactored into another object in the future)
//==================================================================================================

	/**
	 * Sets the emphasis value for this edge.  A value of 0 indicates no emphasis.
	 * 
	 * @param emphasisLevel the emphasis
	 */
	public void setEmphasis(double emphasisLevel);

	/**
	 * Returns the emphasis value of this edge.  0 if not emphasized.
	 * 
	 * @return the emphasis value of this edge.
	 */
	public double getEmphasis();

	/**
	 * Set the alpha, which determines how much of the edge is visible/see through.  0 is 
	 * completely transparent.  This attribute allows transitional for animations.
	 * 
	 * @param alpha the alpha value
	 */
	public void setAlpha(double alpha);

	/**
	 * Get the alpha, which determines how much of the edge is visible/see through.  0 is 
	 * completely transparent.  This attribute allows transitional for animations.
	 * 
	 * @return the alpha value
	 */
	public double getAlpha();
}
