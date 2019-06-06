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

import javax.swing.Icon;
import javax.swing.event.ChangeListener;

import docking.action.DockingActionIf;
import docking.actions.KeyBindingUtils;
import ghidra.framework.plugintool.util.*;
import ghidra.util.Msg;
import resources.ResourceManager;

public class PluginConfigurationModel {
	private static Icon EXPERIMENTAL_ICON =
		ResourceManager.loadImage("images/applications-science.png");
	private final ChangeListener listener;
	private final PluginTool tool;
	private PluginClassManager pluginClassManager;
	private Map<PluginDescription, Plugin> loadedPluginMap = new HashMap<>();
	private Set<PluginDescription> pluginsWithDependenciesSet = new HashSet<>();
	private List<PluginDescription> unStablePluginDescriptions;
	private PluginPackage unstablePackage;

	public PluginConfigurationModel(PluginTool tool) {
		this(tool, e -> {
			// dummy listener
		});
	}

	public PluginConfigurationModel(PluginTool tool, ChangeListener listener) {
		this.tool = tool;
		this.listener = listener;
		pluginClassManager = tool.getPluginClassManager();
		initLoadedPlugins();
		unStablePluginDescriptions = pluginClassManager.getNonReleasedPluginDescriptions();
		if (!unStablePluginDescriptions.isEmpty()) {
			unstablePackage = new PluginPackage("Experimental", EXPERIMENTAL_ICON,
				"This package contains plugins that are not fully tested and/or documented." +
					"You must add these plugins individually.  Adding these plugins could cause the tool" +
					" to become unstable.",
				Integer.MAX_VALUE) {
				@Override
				public boolean isfullyAddable() {
					return false;
				}
			};
		}
	}

	public List<PluginPackage> getPluginPackages() {
		List<PluginPackage> pluginPackages = pluginClassManager.getPluginPackages();
		List<PluginPackage> packagesWithStablePlugins = new ArrayList<>();
		for (PluginPackage pluginPackage : pluginPackages) {
			if (pluginClassManager.getReleasedPluginDescriptions(pluginPackage).size() > 0) {
				packagesWithStablePlugins.add(pluginPackage);
			}
		}
		if (unstablePackage != null) {
			packagesWithStablePlugins.add(unstablePackage);
		}
		return packagesWithStablePlugins;
	}

	public List<PluginDescription> getPluginDescriptions(PluginPackage pluginPackage) {
		if (pluginPackage == unstablePackage) {
			return unStablePluginDescriptions;
		}
		return pluginClassManager.getReleasedPluginDescriptions(pluginPackage);
	}

	/**
	 * Gets the loaded plugins from the tool and populates the loadedPluginMap and the 
	 * pluginsWithDependenciesSet. 
	 */
	private void initLoadedPlugins() {
		loadedPluginMap.clear();
		pluginsWithDependenciesSet.clear();
		List<Plugin> list = tool.getManagedPlugins();
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
		for (int i = 0; i < plugins.size(); i++) {
			Plugin p = plugins.get(i);
			if (p.dependsUpon(plugin)) {
				pluginsWithDependenciesSet.add(getPluginDescription(plugin));
			}
		}
	}

	private PluginDescription getPluginDescription(Plugin plugin) {
		String className = plugin.getClass().getName();
		return pluginClassManager.getPluginDescription(className);
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
			tool.addPlugin(pluginDescription.getPluginClass().getName());
		}
		catch (PluginException e) {
			Msg.showError(this, null, "Error Loading Plugin", e.getMessage(), e);
		}
		initLoadedPlugins();
		listener.stateChanged(null);
	}

	public void removeAllPlugins(PluginPackage pluginPackage) {
		List<PluginDescription> pluginDescriptions = getPluginDescriptions(pluginPackage);
		List<Plugin> loadedPlugins = new ArrayList<>();
		for (PluginDescription pluginDescription : pluginDescriptions) {
			if (isLoaded(pluginDescription)) {
				loadedPlugins.add(loadedPluginMap.get(pluginDescription));
			}
		}
		tool.removePlugins(loadedPlugins.toArray(new Plugin[loadedPlugins.size()]));
		initLoadedPlugins();
		listener.stateChanged(null);
	}

	public void addAllPlugins(PluginPackage pluginPackage) {
		List<PluginDescription> pluginDescriptions = getPluginDescriptions(pluginPackage);

		List<String> pluginClasseNames = new ArrayList<>();
		for (PluginDescription pluginDescription : pluginDescriptions) {
			if (!isLoaded(pluginDescription)) {
				pluginClasseNames.add(pluginDescription.getPluginClass().getName());
			}
		}
		try {
			tool.addPlugins(pluginClasseNames.toArray(new String[pluginClasseNames.size()]));
		}
		catch (PluginException e) {
			Msg.showError(this, null, "Error Loading Plugin(s) ", e.getMessage(), e);
		}
		initLoadedPlugins();
		listener.stateChanged(null);
	}

	public void removePlugin(PluginDescription pluginDescription) {
		Plugin plugin = loadedPluginMap.get(pluginDescription);
		if (plugin != null) {
			tool.removePlugins(new Plugin[] { plugin });
		}
		initLoadedPlugins();
		listener.stateChanged(null);
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
	 * Returns all of the actions loaded by the Plugin represented by the given PluginDescription.
	 * An empty list will be returned if no actions are loaded or if the plugin has not been 
	 * loaded.
	 * @param pluginDescription The description for which to find loaded actions.
	 * @return all of the actions loaded by the Plugin represented by the given PluginDescription.
	 */
	public Set<DockingActionIf> getActionsForPlugin(PluginDescription pluginDescription) {
		if (!isLoaded(pluginDescription)) {
			return Collections.emptySet();
		}

		return KeyBindingUtils.getKeyBindingActionsForOwner(tool, pluginDescription.getName());
	}

	/**
	 * Return the names of the plugins that are dependent on some service
	 * that the plugin corresponding to the given PluginDescription provides.
	 * @param pd PluginDescription of the plugin
	 */
	public List<PluginDescription> getDependencies(PluginDescription pd) {
		Plugin plugin = loadedPluginMap.get(pd);
		return (plugin != null) ? getDependencies(plugin, tool.getManagedPlugins())
				: Collections.emptyList();
	}

	private List<PluginDescription> getDependencies(Plugin plugin, List<Plugin> plugins) {
		HashSet<PluginDescription> set = new HashSet<>();

		// find out all plugins that depend on this plugin
		for (int i = 0; i < plugins.size(); i++) {
			Plugin p = plugins.get(i);
			if (p.dependsUpon(plugin)) {
				set.add(p.getPluginDescription());
			}
		}
		return new ArrayList<>(set);
	}

	public List<PluginDescription> getAllPluginDescriptions() {
		return pluginClassManager.getAllPluginDescriptions();
	}

}
