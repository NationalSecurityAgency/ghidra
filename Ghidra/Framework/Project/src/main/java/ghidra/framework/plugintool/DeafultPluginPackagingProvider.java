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

import ghidra.framework.plugintool.util.*;

/**
 * The default plugin package provider that uses the {@link PluginClassManager} to supply packages
 */
public class DeafultPluginPackagingProvider implements PluginPackagingProvider {

	private PluginClassManager pluginClassManager;

	DeafultPluginPackagingProvider(PluginClassManager pluginClassManager) {
		this.pluginClassManager = pluginClassManager;
	}

	@Override
	public List<PluginPackage> getPluginPackages() {
		return pluginClassManager.getPluginPackages();
	}

	@Override
	public List<PluginDescription> getPluginDescriptions() {
		return pluginClassManager.getManagedPluginDescriptions();
	}

	@Override
	public PluginDescription getPluginDescription(String pluginClassName) {
		return pluginClassManager.getPluginDescription(pluginClassName);
	}

	@Override
	public List<PluginDescription> getPluginDescriptions(PluginPackage pluginPackage) {
		return pluginClassManager.getPluginDescriptions(pluginPackage);
	}

	@Override
	public PluginPackage getUnstablePluginPackage() {
		return UNSTABLE_PACKAGE;
	}

	@Override
	public List<PluginDescription> getUnstablePluginDescriptions() {
		return pluginClassManager.getUnstablePluginDescriptions();
	}

}
