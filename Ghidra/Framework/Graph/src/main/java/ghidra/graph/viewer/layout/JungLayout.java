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

import edu.uci.ics.jung.algorithms.layout.Layout;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;

/**
 * A class that defines a simple Jung {@link Layout} interface for 
 * {@link VisualVertex Visual Vertices} and {@link VisualEdge}s 
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
//@formatter:off
public class JungLayout<V extends VisualVertex, 
	                    E extends VisualEdge<V>> 
	extends JungWrappingVisualGraphLayoutAdapter<V, E> {
//@formatter:on

	public JungLayout(Layout<V, E> jungLayout) {
		super(jungLayout);
	}

	@Override
	protected Layout<V, E> cloneJungLayout(VisualGraph<V, E> newGraph) {

		Layout<V, E> newJungLayout = super.cloneJungLayout(newGraph);
		return new JungLayout<>(newJungLayout);
	}

	Layout<?, ?> getJungLayout() {
		return delegate;
	}
}
