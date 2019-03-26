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

import java.lang.reflect.Constructor;
import java.util.HashSet;
import java.util.Set;

import edu.uci.ics.jung.algorithms.layout.*;
import edu.uci.ics.jung.graph.Graph;
import ghidra.graph.VisualGraph;
import ghidra.graph.graphs.JungDirectedVisualGraph;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import ghidra.util.Msg;
import util.CollectionUtils;

/**
 * A factory to produce {@link JungLayoutProvider}s that can be used to layout 
 * {@link VisualGraph}s
 */
public class JungLayoutProviderFactory {

	//@formatter:off
	public static <V extends VisualVertex, 
				   E extends VisualEdge<V>, 
				   G extends JungDirectedVisualGraph<V, E>> 
					
		Set<JungLayoutProvider<V, E, G>> createLayouts() {
	//@formatter:on

		Set<JungLayoutProvider<V, E, G>> providers = new HashSet<>();

		//@formatter:off
		providers.addAll(
			CollectionUtils.asSet(
				// create("DAG Layout", DAGLayout.class),
				create("Circle Layout", CircleLayout.class),
				create("Spring Layout", SpringLayout.class),
				create("KK Layout", KKLayout.class),
				create("ISOM Layout", ISOMLayout.class)		
		));
		//@formatter:on

		return providers;
	}

	//@formatter:off
	@SuppressWarnings("rawtypes") // Layout should be templated; we are using it generically
	public static <V extends VisualVertex, 
				   E extends VisualEdge<V>, 
				   G extends JungDirectedVisualGraph<V, E>> 
					
		JungLayoutProvider<V, E, G> create(String name, Class<? extends Layout> layoutClass) {
	//@formatter:on

		JungLayoutProvider<V, E, G> provider = new JungLayoutProvider<V, E, G>() {

			@Override
			public String getLayoutName() {
				return name;
			}

			@Override
			protected Layout<V, E> createLayout(G g) {

				try {
					Constructor<?> c = layoutClass.getConstructor(Graph.class);

					// we are using the interface to this factory to get compile-time 
					// enforcement of types; at this point we cannot enforce types using a 
					// class object to create a new layout
					@SuppressWarnings("unchecked")
					Layout<V, E> l = (Layout<V, E>) c.newInstance(g);
					return l;
				}
				catch (Exception e) {
					Msg.error(JungLayoutProviderFactory.class,
						"Unable to construct layout: " + layoutClass, e);
				}
				return null;
			}

		};
		return provider;
	}
}
