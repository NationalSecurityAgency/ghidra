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
package ghidra.app.plugin.core.functiongraph.graph.layout;

import ghidra.app.plugin.core.functiongraph.FunctionGraphPlugin;
import ghidra.framework.options.Options;

/**
 * An interface for {@link FGLayout} options
 */
public interface FGLayoutOptions {

	public static final String OWNER = FunctionGraphPlugin.class.getSimpleName();

	/**
	 * Called during setup for this class to register its options with the given {@link Options}
	 * object
	 * 
	 * @param options the tool options
	 */
	public void registerOptions(Options options);

	/**
	 * Called when the given {@link Options} object has changed.  This class will update its 
	 * options with the values from the given options object.
	 * 
	 * @param options the tool options
	 */
	public void loadOptions(Options options);

	/**
	 * Returns true if the given option name, when changed, requires that the current graph be
	 * reloaded for the change to take effect
	 * 
	 * @param optionName the changed option name
	 * @return true if a relayout is required
	 */
	public boolean optionChangeRequiresRelayout(String optionName);
}
