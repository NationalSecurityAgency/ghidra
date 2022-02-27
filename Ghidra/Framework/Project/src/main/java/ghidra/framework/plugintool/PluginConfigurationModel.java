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

import java.util.*;

import ghidra.framework.plugintool.util.*;
import ghidra.util.Msg;
import utility.function.Callback;
import utility.function.Dummy;

public class PluginConfigurationModel {

	private final PluginInstaller pluginInstaller;
	private PluginPackagingProvider pluginPackagingProvider;
	private Callback listener = Callback.dummy();
	private Map<PluginDescription, Plugin> loadedPluginMap = new HashMap<>();
	private Set<PluginDescription> pluginsWithDependenciesSet = new HashSet<>();
	private List<PluginDescription> unStablePluginDescriptions;
	private PluginPackage unstablePackage;

	public PluginConfigurationModel(PluginTool tool) {
		this(new DefaultPluginInstaller(tool),
			new DeafultPluginPackagingProvider(tool.getPluginClassManager()));
	}

	public PluginConfigurationModel(PluginInstaller pluginInstaller,
			PluginPackagingProvider pluginPackagingProvider) {

		this.pluginInstaller = pluginInstaller;
		this.pluginPackagingProvider = pluginPackagingProvider;
		initLoadedPlugins();

		unstablePackage = pluginPackagingProvider.getUnstablePluginPackage();
		unStablePluginDescriptions = pluginPackagingProvider.getUnstablePluginDescriptions();
	}

	public void setChangeCallback(Callback listener) {
		this.listener = Dummy.ifNull(listener);
	}

	public List<PluginPackage> getPluginPackages() {
		List<PluginPackage> pluginPackages = pluginPackagingProvider.getPluginPackages();
		List<PluginPackage> packagesWithStablePlugins = new ArrayList<>();
		for (PluginPackage pluginPackage : pluginPackages) {
			if (pluginPackagingProvider.getPluginDescriptions(pluginPackage).size() > 0) {
				packagesWithStablePlugins.add(pluginPackage);
			}
		}

		if (!unStablePluginDescriptions.isEmpty()) {
			packagesWithStablePlugins.add(unstablePackage);
		}

		return packagesWithStablePlugins;
	}

	public List<PluginDescription> getPluginDescriptions(PluginPackage pluginPackage) {
		if (pluginPackage == unstablePackage) {
			return unStablePluginDescriptions;
		}
		return pluginPackagingProvider.getPluginDescriptions(pluginPackage);
	}

	/**
	 * Gets the loaded plugins from the tool and populates the loadedPluginMap and the
	 * pluginsWithDependenciesSet.
	 */
	private void initLoadedPlugins() {
		loadedPluginMap.clear();
		pluginsWithDependenciesSet.clear();
		List<Plugin> list = pluginInstaller.getManagedPlugins();
		for (Plugin plugin : list) {
			loadedPluginMap.put(getPluginDescription(plugin), plugin);
			findDependencies(plugin, list);
		}
	}

	/**
	 *  Find out all plugins that depend on a plugin and add them to the dependency set
	 * @param plugin the plugin to check if other plugins depend on it.
	 * @param plugins the list of all loaded plugins.
	 */
	private void findDependencies(Plugin plugin, List<Plugin> plugins) {
		for (Plugin p : plugins) {
			if (p.dependsUpon(plugin)) {
				pluginsWithDependenciesSet.add(getPluginDescription(plugin));
			}
		}
	}

	private PluginDescription getPluginDescription(Plugin plugin) {
		String className = plugin.getClass().getName();
		return pluginPackagingProvider.getPluginDescription(className);
	}

	public boolean isLoaded(PluginDescription pluginDescription) {
		return loadedPluginMap.containsKey(pluginDescription);
	}

	public PluginPackageState getPackageState(PluginPackage pluginPackage) {
		boolean someInTool = false;
		boolean someNotInTool = false;
		List<PluginDescription> pluginDescriptions = getPluginDescriptions(pluginPackage);

		for (PluginDescription pluginDescription : pluginDescriptions) {
			if (isLoaded(pluginDescription)) {
				someInTool = true;
			}
			else {
				someNotInTool = true;
			}
		}
		if (!someInTool) {
			return PluginPackageState.NO_PLUGINS_LOADED;
		}
		else if (!someNotInTool) {
			return PluginPackageState.ALL_PLUGINS_LOADED;
		}
		return PluginPackageState.SOME_PLUGINS_LOADED;
	}

	public void addPlugin(PluginDescription pluginDescription) {
		try {
			String name = pluginDescription.getPluginClass().getName();
			pluginInstaller.addPlugins(Arrays.asList(name));
		}
		catch (PluginException e) {
			Msg.showError(this, null, "Error Loading Plugin", e.getMessage(), e);
		}
		initLoadedPlugins();
		listener.call();
	}

	public void removeAllPlugins(PluginPackage pluginPackage) {
		List<PluginDescription> pluginDescriptions = getPluginDescriptions(pluginPackage);
		List<Plugin> loadedPlugins = new ArrayList<>();
		for (PluginDescription pluginDescription : pluginDescriptions) {
			if (isLoaded(pluginDescription)) {
				loadedPlugins.add(loadedPluginMap.get(pluginDescription));
			}
		}
		pluginInstaller.removePlugins(loadedPlugins);
		initLoadedPlugins();
		listener.call();
	}

	public void addSupportedPlugins(PluginPackage pluginPackage) {

		PluginStatus activationLevel = pluginPackage.getActivationLevel();
		List<PluginDescription> pluginDescriptions = getPluginDescriptions(pluginPackage);
		List<String> pluginClasseNames = new ArrayList<>();
		for (PluginDescription pluginDescription : pluginDescriptions) {

			PluginStatus status = pluginDescription.getStatus();
			if (status.compareTo(activationLevel) > 0) {
				continue; // status is not good enough to be activated (e.g., UNSTABLE)
			}

			if (!isLoaded(pluginDescription)) {
				pluginClasseNames.add(pluginDescription.getPluginClass().getName());
			}
		}
		try {
			pluginInstaller.addPlugins(pluginClasseNames);
		}
		catch (PluginException e) {
			Msg.showError(this, null, "Error Loading Plugin(s) ", e.getMessage(), e);
		}
		initLoadedPlugins();
		listener.call();
	}

	public boolean hasOnlyUnstablePlugins(PluginPackage pluginPackage) {
		List<PluginDescription> pluginDescriptions = getPluginDescriptions(pluginPackage);
		for (PluginDescription pluginDescription : pluginDescriptions) {
			PluginStatus status = pluginDescription.getStatus();
			if (status.compareTo(PluginStatus.UNSTABLE) < 0) {
				return false;
			}
		}
		return true;
	}

	public void removePlugin(PluginDescription pluginDescription) {
		Plugin plugin = loadedPluginMap.get(pluginDescription);
		if (plugin != null) {
			pluginInstaller.removePlugins(Arrays.asList(plugin));
		}
		initLoadedPlugins();
		listener.call();
	}

	/**
	 * Return whether the plugin corresponding to the given PluginDescription
	 * has other plugins depending on a service it provides.
	 * @param pluginDependency PluginDescription of the plugin
	 * @return true if the plugin corresponding to the given PluginDescription
	 * has at least one plugin depending on a service it provides
	 */
	public boolean hasDependencies(PluginDescription pluginDependency) {
		return pluginsWithDependenciesSet.contains(pluginDependency);
	}

	/**
	 * Return the descriptions of the plugins that are dependent on some service that the plugin
	 * corresponding to the given PluginDescription provides.
	 *
	 * @param pd PluginDescription of the plugin
	 * @return the descriptions
	 */
	public List<PluginDescription> getDependencies(PluginDescription pd) {
		Plugin plugin = loadedPluginMap.get(pd);
		return (plugin != null) ? getDependencies(plugin, pluginInstaller.getManagedPlugins())
				: Collections.emptyList();
	}

	private List<PluginDescription> getDependencies(Plugin plugin, List<Plugin> plugins) {
		HashSet<PluginDescription> set = new HashSet<>();

		// find out all plugins that depend on this plugin
		for (Plugin p : plugins) {
			if (p.dependsUpon(plugin)) {
				set.add(p.getPluginDescription());
			}
		}
		return new ArrayList<>(set);
	}

	public List<PluginDescription> getAllPluginDescriptions() {
		return pluginPackagingProvider.getPluginDescriptions();
	}
}
