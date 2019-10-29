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

import javax.swing.Icon;

import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A layout provider creates {@link VisualGraphLayout} instances.  This class provides a name
 * and icon for use in a UI.  These features can be used to create a menu of layouts that may 
 * be applied. 
 * 
 * <P>The pattern of usage for this class is for it to create the layout that it represents and
 * then to apply the locations of that layout to the vertices (and edges, in the case of
 * articulating edges) of the graph before returning the new layout.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 * @param <G> the graph type
 */
//@formatter:off
public interface LayoutProvider<V extends VisualVertex, 
								E extends VisualEdge<V>, 
								G extends VisualGraph<V, E>>
	
	extends ExtensionPoint {
//@formatter:on

	/**
	 * Returns a new instance of the layout that this class provides
	 * 
	 * @param graph the graph
	 * @param monitor a task monitor 
	 * @return the new layout
	 * @throws CancelledException if the monitor was cancelled
	 */
	public VisualGraphLayout<V, E> getLayout(G graph, TaskMonitor monitor)
			throws CancelledException;

	/**
	 * Returns the name of this layout
	 * 
	 * @return the name of this layout
	 */
	public String getLayoutName();

	/**
	 * Returns an icon that can be used to show the provider a menu or toolbar.  This may 
	 * return null, as an icon is not a requirement.
	 * 
	 * @return an icon that can be used to show the provider a menu or toolbar
	 */
	public Icon getActionIcon();

	/**
	 * Returns an arbitrary value that is relative to other LayoutProviders.  The higher the 
	 * value the more preferred the provider will be over other providers.
	 * 
	 * @return the priority
	 */
	public int getPriorityLevel();

}
