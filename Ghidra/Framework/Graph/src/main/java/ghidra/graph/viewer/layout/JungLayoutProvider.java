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

import java.util.Objects;

import javax.swing.Icon;

import edu.uci.ics.jung.algorithms.layout.Layout;
import ghidra.graph.VisualGraph;
import ghidra.graph.graphs.JungDirectedVisualGraph;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

/**
 * A layout provider that works on {@link JungDirectedVisualGraph}s.  This class allows the 
 * Jung layouts to be used where {@link VisualGraph}s are used.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 * @param <G> the graph type
 */
//@formatter:off
public abstract class JungLayoutProvider<V extends VisualVertex, 
                                         E extends VisualEdge<V>, 
                                         G extends JungDirectedVisualGraph<V, E>>
		extends AbstractLayoutProvider<V, E, G> {
//@formatter:on

	private static final Icon DEFAULT_ICON = ResourceManager.loadImage("images/color_swatch.png");

	protected abstract Layout<V, E> createLayout(G g);

	@Override
	public VisualGraphLayout<V, E> getLayout(G g, TaskMonitor monitor) throws CancelledException {

		Objects.requireNonNull(g);

		Layout<V, E> jungLayout = createLayout(g);

		initVertexLocations(g, jungLayout);

		return new JungLayout<>(jungLayout);
	}

	// Note: each provider really should load its own icon so that the toolbar item can 
	//       signal to the user which layout is active
	@Override
	public Icon getActionIcon() {
		return DEFAULT_ICON;
	}
}
