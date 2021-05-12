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

import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * A version of {@link LayoutProvider} that is discoverable at runtime.   Layouts that do not wish 
 * to be discoverable should implement {@link LayoutProvider} directly, not this interface.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 * @param <G> the graph type
 */
//@formatter:off
public interface LayoutProviderExtensionPoint<V extends VisualVertex, 
											  E extends VisualEdge<V>, 
											  G extends VisualGraph<V, E>>
	
	extends LayoutProvider<V, E, G>, ExtensionPoint {
//@formatter:on

}
