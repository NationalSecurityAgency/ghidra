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
import java.util.Collection;

import javax.swing.Icon;

import edu.uci.ics.jung.algorithms.layout.Layout;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;

/**
 * A base implementation of {@link LayoutProvider} that stubs some default methods.
 *
 * <P>Some clients extends this class and adapt their graph to use one of the provided Jung
 * layouts.  Other clients will implement the interface of this class to create a custom layout.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 * @param <G> the graph type
 */
//@formatter:off
public abstract class AbstractLayoutProvider<V extends VisualVertex, 
									         E extends VisualEdge<V>, 
									         G extends VisualGraph<V, E>>

	implements LayoutProviderExtensionPoint<V, E, G> {
//@formatter:on

	@Override
	public Icon getActionIcon() {
		return null;
	}

	@Override
	public int getPriorityLevel() {
		return 0;
	}

	/**
	 * Gives all vertices of the graph an initial, non-null location.  This only works if the
	 * graph has been built before this method is called.  
	 * 
	 * <P>Some graphs that have a layout will perform this same function as vertices are added.
	 * 
	 * @param g the graph
	 * @param layout the graph layout
	 */
	protected void initVertexLocations(G g, Layout<V, E> layout) {
		Collection<V> vertices = g.getVertices();
		for (V v : vertices) {
			Point2D p = layout.apply(v);
			v.setLocation(p);
		}
	}
}
