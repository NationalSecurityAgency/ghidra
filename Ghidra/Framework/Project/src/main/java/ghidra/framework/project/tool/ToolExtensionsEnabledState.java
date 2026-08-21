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
import java.util.*;
import java.util.stream.Collectors;

import docking.widgets.OptionDialog;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.dialog.PluginInstallerDialog;
import ghidra.framework.plugintool.util.PluginDescription;
import ghidra.framework.project.extensions.ExtensionInstallationInfo;
import ghidra.util.SystemUtilities;
import ghidra.util.classfinder.ClassFileInfo;
import ghidra.util.extensions.ExtensionDetails;

/**
 * The default extension state for a {@link PluginTool}.
 */
class ToolExtensionsEnabledState implements ExtensionsEnabledState {

	private static String PLUGIN_SUFFIX = Plugin.class.getSimpleName();

	private PluginTool tool;

	ToolExtensionsEnabledState(PluginTool tool) {
		this.tool = tool;
	}

	@Override
	public Map<String, Set<ClassFileInfo>> getAllKnownExtensions() {

		Set<ExtensionInstallationInfo> extensions = getExtensions();
		if (extensions.isEmpty()) {
			return Map.of();
		}

		Map<String, Set<ClassFileInfo>> result = new HashMap<>();
		for (ExtensionInstallationInfo info : extensions) {

			ExtensionDetails extension = info.getExtension();
			Set<ClassFileInfo> plugins = getPlugins(info);
			if (plugins.isEmpty()) {
				continue;
			}

			result.put(extension.getName(), plugins);
		}
		return result;
	}

	private Set<ClassFileInfo> getPlugins(ExtensionInstallationInfo info) {

		Set<ClassFileInfo> result = new HashSet<>();
		Set<ClassFileInfo> classInfos = info.getClassInfos();
		for (ClassFileInfo classInfo : classInfos) {
			String suffix = classInfo.suffix();
			if (PLUGIN_SUFFIX.equals(suffix)) {
				result.add(classInfo);
			}
		}
		return result;
	}

	@Override
	public void removeInstalledPlugins(Set<ClassFileInfo> plugins) {
		List<Plugin> activePlugins = tool.getManagedPlugins();

		Set<String> activeClassNames = activePlugins.stream()
				.map(Plugin::getClass)
				.map(Class::getName)
				.collect(Collectors.toSet());

		Iterator<ClassFileInfo> it = plugins.iterator();
		while (it.hasNext()) {
			ClassFileInfo info = it.next();
			String name = info.name();
			if (activeClassNames.contains(name)) {
				it.remove();
			}
		}
	}

	@Override
	public void propmtToConfigureNewPlugins(Set<ClassFileInfo> plugins) {
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

	private static Set<ExtensionInstallationInfo> getExtensions() {

		Set<ExtensionInstallationInfo> infos = ExtensionInstallationInfo.get();
		Iterator<ExtensionInstallationInfo> it = infos.iterator();
		while (it.hasNext()) {

			ExtensionInstallationInfo info = it.next();
			ExtensionDetails e = info.getExtension();
			if (isRepoExtension(e) || e.isPendingUninstall()) {
				it.remove();
			}
		}

		return infos;
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
	private List<PluginDescription> getPluginDescriptions(Set<ClassFileInfo> plugins) {

		// First define the list of plugin descriptions to return
		List<PluginDescription> descriptions = new ArrayList<>();

		// Get all plugins that have been loaded
		PluginsConfiguration pluginsConfiguration = tool.getPluginsConfiguration();
		List<PluginDescription> allPluginDescriptions =
			pluginsConfiguration.getManagedPluginDescriptions();

		// see if an entry exists in the list of all loaded plugins
		for (ClassFileInfo info : plugins) {
			String pluginName = info.simpleName();

			Optional<PluginDescription> desc = allPluginDescriptions.stream()
					.filter(d -> pluginName.equals(d.getName()))
					.findAny();
			if (desc.isPresent()) {
				descriptions.add(desc.get());
			}
		}

		return descriptions;
	}

}
