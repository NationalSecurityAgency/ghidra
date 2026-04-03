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
package ghidra.framework.project.tool;

import java.io.File;
import java.net.URL;
import java.util.*;
import java.util.stream.Collectors;

import docking.widgets.OptionDialog;
import generic.json.Json;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.dialog.PluginInstallerDialog;
import ghidra.framework.plugintool.util.PluginDescription;
import ghidra.util.SystemUtilities;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.extensions.ExtensionDetails;
import ghidra.util.extensions.ExtensionUtils;
import utilities.util.FileUtilities;

/**
 * The default extension state for a {@link PluginTool}.
 */
class ToolExtensionsEnabledState implements ExtensionsEnabledState {

	private PluginTool tool;

	ToolExtensionsEnabledState(PluginTool tool) {
		this.tool = tool;
	}

	@Override
	public Map<String, Set<Class<?>>> getAllKnownExtensions() {

		Set<ExtensionDetails> extensions = getExtensions();
		if (extensions.isEmpty()) {
			return Map.of();
		}

		Map<String, Set<Class<?>>> plugins = new HashMap<>();
		Set<PluginPath> pluginPaths = getAllPluginPaths();
		for (ExtensionDetails extension : extensions) {
			Set<Class<?>> classes = findPluginsLoadedFromExtension(extension, pluginPaths);
			plugins.put(extension.getName(), classes);
		}
		return plugins;
	}

	@Override
	public void removeInstalledPlugins(Set<Class<?>> plugins) {
		List<Plugin> activePlugins = tool.getManagedPlugins();
		for (Plugin plugin : activePlugins) {
			Class<? extends Plugin> clazz = plugin.getClass();
			plugins.remove(clazz);
		}
	}

	@Override
	public void propmtToConfigureNewPlugins(Set<Class<?>> plugins) {
		// Offer the user a chance to configure any newly discovered plugins
		int option = OptionDialog.showYesNoDialog(tool.getToolFrame(), "New Plugins Found!",
			"New extension plugins detected. Would you like to configure them?");
		if (option == OptionDialog.YES_OPTION) {
			List<PluginDescription> pluginDescriptions = getPluginDescriptions(plugins);
			PluginInstallerDialog pluginInstaller = new PluginInstallerDialog("New Plugins Found!",
				tool, new PluginConfigurationModel(tool), pluginDescriptions);
			tool.showDialog(pluginInstaller);
		}
	}

	private static Set<PluginPath> getAllPluginPaths() {
		Set<PluginPath> paths = new HashSet<>();
		List<Class<? extends Plugin>> plugins = ClassSearcher.getClasses(Plugin.class);
		for (Class<? extends Plugin> plugin : plugins) {
			paths.add(new PluginPath(plugin));
		}
		return paths;
	}

	private static Set<ExtensionDetails> getExtensions() {
		Set<ExtensionDetails> installedExtensions = ExtensionUtils.getActiveInstalledExtensions();
		return installedExtensions.stream()
				.filter(e -> !isRepoExtension(e))
				.collect(Collectors.toSet());
	}

	/**
	 * We wish to ignore extension modules that live in the repo installation dir. This keeps 
	 * developers from getting prompted while developing.
	 * @param e the extension
	 * @return true if not a development extension
	 */
	private static boolean isRepoExtension(ExtensionDetails e) {
		// Repo extensions live in a known installation folder in development mode.  They do not
		// exist in a release.
		if (SystemUtilities.isInDevelopmentMode()) {
			if (e.isInstalledInInstallationFolder()) {
				// Checking for a build file is an easy way to find repo extensions
				File dir = e.getInstallDir();
				File buildFile = new File(dir, "build.gradle");
				return buildFile.exists();
			}
		}
		return false;
	}

	/**
	 * Finds all plugin classes loaded from a particular extension folder.
	 * <p>
	 * This uses the {@link ClassSearcher} to find all <code>Plugin.class</code> objects on the
	 * classpath. For each class, the original resource file is compared against the
	 * given extension folder and the jar files for that extension. 
	 *
	 * @param extension the extension from which to find plugins
	 * @param pluginPaths all loaded plugin paths
	 * @return list of {@link Plugin} classes, or empty list if none found
	 */
	private static Set<Class<?>> findPluginsLoadedFromExtension(ExtensionDetails extension,
			Set<PluginPath> pluginPaths) {

		if (!extension.isInstalled()) {
			return Collections.emptySet();
		}

		// Find any jar files in the directory provided
		Set<URL> jarPaths = extension.getLibraries();

		// Now get all Plugin.class file paths and see if any of them were loaded from one of the 
		// extension the given extension directory
		Set<Class<?>> result = new HashSet<>();
		for (PluginPath pluginPath : pluginPaths) {
			if (pluginPath.isFrom(extension.getInstallDir())) {
				result.add(pluginPath.getPluginClass());
				continue;
			}

			for (URL jarUrl : jarPaths) {
				if (pluginPath.isFrom(jarUrl)) {
					result.add(pluginPath.getPluginClass());
				}
			}
		}
		return result;
	}

	/**
	 * Finds all {@link PluginDescription} objects that match a given set of plugin classes. This
	 * effectively tells the caller which of the given plugins have been loaded by the class loader.
	 * <p>
	 * Note that this method does not take path/package information into account when finding
	 * plugins; in the example above, if there is more than one plugin with the name "FooPlugin",
	 * only one will be found (the one found is not guaranteed to be the first).
	 *
	 * @param plugins the list of plugin classes to search for
	 * @return list of plugin descriptions
	 */
	private List<PluginDescription> getPluginDescriptions(Set<Class<?>> plugins) {

		// First define the list of plugin descriptions to return
		List<PluginDescription> descriptions = new ArrayList<>();

		// Get all plugins that have been loaded
		PluginsConfiguration pluginsConfiguration = tool.getPluginsConfiguration();
		List<PluginDescription> allPluginDescriptions =
			pluginsConfiguration.getManagedPluginDescriptions();

		// see if an entry exists in the list of all loaded plugins
		for (Class<?> plugin : plugins) {
			String pluginName = plugin.getSimpleName();

			Optional<PluginDescription> desc = allPluginDescriptions.stream()
					.filter(d -> (pluginName.equals(d.getName())))
					.findAny();
			if (desc.isPresent()) {
				descriptions.add(desc.get());
			}
		}

		return descriptions;
	}

	private static class PluginPath {
		private Class<? extends Plugin> pluginClass;
		private String pluginLocation;
		private File pluginFile;

		PluginPath(Class<? extends Plugin> pluginClass) {
			this.pluginClass = pluginClass;
			String name = pluginClass.getName();
			URL url = pluginClass.getResource('/' + name.replace('.', '/') + ".class");
			this.pluginLocation = url.getPath();
			this.pluginFile = new File(pluginLocation);
		}

		public boolean isFrom(File dir) {
			return FileUtilities.isPathContainedWithin(dir, pluginFile);
		}

		boolean isFrom(URL jarUrl) {
			String jarPath = jarUrl.getPath();
			return pluginLocation.contains(jarPath);
		}

		Class<? extends Plugin> getPluginClass() {
			return pluginClass;
		}

		@Override
		public String toString() {
			return Json.toString(this);
		}
	}
}
