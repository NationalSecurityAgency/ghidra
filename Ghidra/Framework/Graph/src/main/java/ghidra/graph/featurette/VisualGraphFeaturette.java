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
package ghidra.graph.featurette;

import ghidra.framework.options.SaveState;
import ghidra.graph.VisualGraph;
import ghidra.graph.VisualGraphComponentProvider;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;

/**
 * An interface that represents a sub-feature of a {@link VisualGraphComponentProvider}.  This
 * allows the base provider to have a set of features ready to be installed by subclasses.
 */
//@formatter:off
public interface VisualGraphFeaturette<V extends VisualVertex, 
									   E extends VisualEdge<V>, 
									   G extends VisualGraph<V, E>> {
//@formatter:on

	/**
	 * Called to initialize this feature when the provider and view are ready
	 * 
	 * @param provider the provider associated with this feature
	 */
	public void init(VisualGraphComponentProvider<V, E, G> provider);

	/**
	 * Called when the client wishes to save configuration state.  Features can add any state
	 * they wish to be persisted over tool launches.
	 * 
	 * @param state the container for state information
	 */
	public void writeConfigState(SaveState state);

	/**
	 * Called when the client wishes to restore configuration state.  Features can read state
	 * previously saved from a call to {@link #writeConfigState(SaveState)}.
	 * 
	 * @param saveState the container for state information
	 */
	public void readConfigState(SaveState saveState);

	/**
	 * Called when the client provider is opened
	 * 
	 * @param provider the provider
	 */
	public void providerOpened(VisualGraphComponentProvider<V, E, G> provider);

	/**
	 * Called when the client provider is closed
	 * 
	 * @param provider the provider
	 */
	public void providerClosed(VisualGraphComponentProvider<V, E, G> provider);

	/**
	 * Called when the provider is being disposed
	 */
	public void remove();

}
