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
package ghidra.framework.plugintool;

import docking.ComponentProvider;
import docking.Tool;

/**
 * Extends the {@link ComponentProvider} to fit into the Plugin architecture by taking in a 
 * {@link PluginTool} which extends {@link Tool}.  Most implementers will want to extend
 * this class instead of the ComponentProvider class because they will want to access the extra
 * methods provided by PluginTool over DockingTool without having to cast the dockingTool variable.
 */

public abstract class ComponentProviderAdapter extends ComponentProvider {
	protected PluginTool tool;

	/**
	 * Creates a new component provider with a default location of
	 * {@link docking.WindowPosition#WINDOW WindowPosition.WINDOW}.
	 * @param tool the plugin tool.
	 * @param name The providers name.  This is used to group similar providers into a tab within
	 *        the same window.
	 * @param owner The owner of this provider, usually a plugin name.
	 */
	public ComponentProviderAdapter(PluginTool tool, String name, String owner) {
		this(tool, name, owner, null);
	}

	/**
	 * Creates a new component provider with a default location of
	 * {@link docking.WindowPosition#WINDOW WindowPosition.WINDOW}.
	 * @param tool the plugin tool.
	 * @param name The providers name.  This is used to group similar providers into a tab within
	 *        the same window.
	 * @param owner The owner of this provider, usually a plugin name
	 * @param contextType the type of context supported by this provider; may be null
	 */
	public ComponentProviderAdapter(PluginTool tool, String name, String owner,
			Class<?> contextType) {
		super(tool, name, owner, contextType);
		this.tool = tool;
	}

	@Override
	public PluginTool getTool() {
		return tool;
	}
}
