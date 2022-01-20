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
 * The default plugin installer that uses a tool to install plugins
 */
public class DefaultPluginInstaller implements PluginInstaller {

	private PluginTool tool;

	DefaultPluginInstaller(PluginTool tool) {
		this.tool = tool;
	}

	@Override
	public List<Plugin> getManagedPlugins() {
		return tool.getManagedPlugins();
	}

	@Override
	public void addPlugins(List<String> pluginClassNames) throws PluginException {
		tool.addPlugins(pluginClassNames);
	}

	@Override
	public void removePlugins(List<Plugin> plugins) {
		tool.removePlugins(plugins);
	}
}
