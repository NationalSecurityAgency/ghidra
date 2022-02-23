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

import java.util.List;

import ghidra.framework.plugintool.util.PluginException;

/**
 * An interface that facilitates the adding and removing of plugins
 */
public interface PluginInstaller {

	/**
	 * Returns all currently installed plugins
	 * @return the plugins
	 */
	public List<Plugin> getManagedPlugins();

	/**
	 * Adds the given plugins to the system
	 * @param pluginClassNames the plugin class names to add
	 * @throws PluginException if there is an issue loading any of the plugins
	 */
	public void addPlugins(List<String> pluginClassNames) throws PluginException;

	/**
	 * Removes the given plugins from the system
	 * @param plugins the plugins
	 */
	public void removePlugins(List<Plugin> plugins);
}
