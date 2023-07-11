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
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import org.jdom.Element;

import docking.widgets.OptionDialog;
import generic.json.Json;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.dialog.PluginInstallerDialog;
import ghidra.framework.plugintool.util.PluginDescription;
import ghidra.framework.project.extensions.ExtensionDetails;
import ghidra.framework.project.extensions.ExtensionUtils;
import ghidra.util.NumericUtilities;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.xml.XmlUtilities;
import utilities.util.FileUtilities;

/**
 * A class to manage saving and restoring of known extension used by this tool.
 */
class ExtensionManager {

	private static final String EXTENSION_ATTRIBUTE_NAME_ENCODED = "ENCODED_NAME";
	private static final String EXTENSION_ATTRIBUTE_NAME = "NAME";
	private static final String EXTENSIONS_XML_NAME = "EXTENSIONS";
	private static final String EXTENSION_ELEMENT_NAME = "EXTENSION";

	private PluginTool tool;
	private Set<Class<?>> newExtensionPlugins = new HashSet<>();

	ExtensionManager(PluginTool tool) {
		this.tool = tool;
	}

	void checkForNewExtensions() {
		if (newExtensionPlugins.isEmpty()) {
			return;
		}

		propmtToConfigureNewPlugins(newExtensionPlugins);
		newExtensionPlugins.clear();
	}

	private void propmtToConfigureNewPlugins(Set<Class<?>> plugins) {

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

	void saveToXml(Element xml) {

		Set<ExtensionDetails> installedExtensions = ExtensionUtils.getActiveInstalledExtensions();
		Element extensionsParent = new Element(EXTENSIONS_XML_NAME);
		for (ExtensionDetails ext : installedExtensions) {
			Element child = new Element(EXTENSION_ELEMENT_NAME);
			String name = ext.getName();
			if (XmlUtilities.hasInvalidXMLCharacters(name)) {
				child.setAttribute(EXTENSION_ATTRIBUTE_NAME_ENCODED, NumericUtilities
						.convertBytesToString(name.getBytes(StandardCharsets.UTF_8)));
			}
			else {
				child.setAttribute(EXTENSION_ATTRIBUTE_NAME, name);
			}

			extensionsParent.addContent(child);
		}

		xml.addContent(extensionsParent);
	}

	void restoreFromXml(Element xml) {

		Set<ExtensionDetails> installedExtensions = getExtensions();
		if (installedExtensions.isEmpty()) {
			return;
		}

		Set<String> knownExtensionNames = getKnownExtensions(xml);
		Set<ExtensionDetails> newExtensions = new HashSet<>(installedExtensions);
		for (ExtensionDetails ext : installedExtensions) {
			if (knownExtensionNames.contains(ext.getName())) {
				newExtensions.remove(ext);
			}
		}

		// Get a list of all plugins contained in those extensions. If there are none, then either 
		// none of the extensions has any plugins, or Ghidra hasn't been restarted since installing 
		// the extension(s), so none of the plugin classes have been loaded. In either case, there 
		// is nothing more to do.
		Set<Class<?>> newPlugins = findLoadedPlugins(newExtensions);
		newExtensionPlugins.addAll(newPlugins);
	}

	private Set<ExtensionDetails> getExtensions() {
		Set<ExtensionDetails> installedExtensions = ExtensionUtils.getActiveInstalledExtensions();
		return installedExtensions.stream()
				.filter(e -> !e.isInstalledInInstallationFolder())
				.collect(Collectors.toSet());
	}

	private Set<String> getKnownExtensions(Element xml) {
		Set<String> knownExtensionNames = new HashSet<>();
		Element extensionsParent = xml.getChild(EXTENSIONS_XML_NAME);
		if (extensionsParent == null) {
			return knownExtensionNames;
		}

		Iterator<?> it = extensionsParent.getChildren(EXTENSION_ELEMENT_NAME).iterator();
		while (it.hasNext()) {
			Element child = (Element) it.next();
			String encodedValue = child.getAttributeValue(EXTENSION_ATTRIBUTE_NAME_ENCODED);
			if (encodedValue != null) {
				byte[] bytes = NumericUtilities.convertStringToBytes(encodedValue);
				String decoded = new String(bytes, StandardCharsets.UTF_8);
				knownExtensionNames.add(decoded);
			}
			else {
				String name = child.getAttributeValue(EXTENSION_ATTRIBUTE_NAME);
				knownExtensionNames.add(name);
			}
		}
		return knownExtensionNames;
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

	private static Set<Class<?>> findLoadedPlugins(Set<ExtensionDetails> extensions) {

		Set<PluginPath> pluginPaths = getPluginPaths();
		Set<Class<?>> extensionPlugins = new HashSet<>();
		for (ExtensionDetails extension : extensions) {
			File installDir = extension.getInstallDir();
			if (installDir == null) {
				continue;
			}

			Set<Class<?>> classes = findPluginsLoadedFromExtension(installDir, pluginPaths);
			extensionPlugins.addAll(classes);
		}

		return extensionPlugins;
	}

	private static Set<PluginPath> getPluginPaths() {
		Set<PluginPath> paths = new HashSet<>();
		List<Class<? extends Plugin>> plugins = ClassSearcher.getClasses(Plugin.class);
		for (Class<? extends Plugin> plugin : plugins) {
			paths.add(new PluginPath(plugin));
		}
		return paths;
	}

	/**
	 * Finds all plugin classes loaded from a particular extension folder.
	 * <p>
	 * This uses the {@link ClassSearcher} to find all <code>Plugin.class</code> objects on the
	 * classpath. For each class, the original resource file is compared against the
	 * given extension folder and the jar files for that extension. 
	 *
	 * @param dir the directory to search, or a jar file
	 * @param pluginPaths all loaded plugin paths
	 * @return list of {@link Plugin} classes, or empty list if none found
	 */
	private static Set<Class<?>> findPluginsLoadedFromExtension(File dir,
			Set<PluginPath> pluginPaths) {

		Set<Class<?>> result = new HashSet<>();

		// Find any jar files in the directory provided
		Set<String> jarPaths = getJarPaths(dir);

		// Now get all Plugin.class file paths and see if any of them were loaded from one of the 
		// extension the given extension directory
		for (PluginPath pluginPath : pluginPaths) {
			if (pluginPath.isFrom(dir)) {
				result.add(pluginPath.getPluginClass());
				continue;
			}

			for (String jarPath : jarPaths) {
				if (pluginPath.isFrom(jarPath)) {
					result.add(pluginPath.getPluginClass());
				}
			}
		}
		return result;
	}

	private static Set<String> getJarPaths(File dir) {
		Set<File> jarFiles = new HashSet<>();
		findJarFiles(dir, jarFiles);
		Set<String> paths = new HashSet<>();
		for (File jar : jarFiles) {
			try {
				URL jarUrl = jar.toURI().toURL();
				paths.add(jarUrl.getPath());
			}
			catch (MalformedURLException e) {
				continue;
			}
		}
		return paths;
	}

	/**
	 * Populates the given list with all discovered jar files found in the given directory and
	 * its subdirectories.
	 *
	 * @param dir the directory to search
	 * @param jarFiles list of found jar files
	 */
	private static void findJarFiles(File dir, Set<File> jarFiles) {
		File[] files = dir.listFiles();
		if (files == null) {
			return;
		}
		for (File f : files) {
			if (f.isDirectory()) {
				findJarFiles(f, jarFiles);
			}

			if (f.isFile() && f.getName().endsWith(".jar")) {
				jarFiles.add(f);
			}
		}
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

		boolean isFrom(String jarPath) {
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
