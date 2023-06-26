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
package ghidra.framework.plugintool.util;

import static java.util.function.Predicate.*;

import java.util.*;
import java.util.function.Predicate;

import org.jdom.Element;

import ghidra.framework.main.ProgramaticUseOnly;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;

/**
 * This class maintains a collection of all plugin classes that are acceptable for a given tool
 * type.  Simple applications with only one plugin type can use the
 * {@link DefaultPluginsConfiguration}.  More complex tools can support a subset of the available
 * plugins. Those tools should create custom subclasses for each tool type, that filter out plugins
 * that are not appropriate for that tool type.
 */
public abstract class PluginsConfiguration {

	private Map<PluginPackage, List<PluginDescription>> descriptionsByPackage = new HashMap<>();
	private Map<String, PluginDescription> descriptionsByName = new HashMap<>();

	protected PluginsConfiguration() {
		populatePluginDescriptionMaps();
	}

	protected abstract boolean accepts(Class<? extends Plugin> pluginClass);

	private Predicate<Class<? extends Plugin>> createFilter() {
		Predicate<Class<? extends Plugin>> ignore = ProgramaticUseOnly.class::isAssignableFrom;
		return not(ignore).and(c -> accepts(c));
	}

	private void populatePluginDescriptionMaps() {

		Predicate<Class<? extends Plugin>> classFilter = createFilter();
		List<Class<? extends Plugin>> classes = ClassSearcher.getClasses(Plugin.class, classFilter);

		for (Class<? extends Plugin> pluginClass : classes) {
			if (!PluginUtils.isValidPluginClass(pluginClass)) {
				Msg.warn(this, "Plugin does not have valid constructor! Skipping " + pluginClass);
				continue;
			}

			PluginDescription pd = PluginDescription.getPluginDescription(pluginClass);
			descriptionsByName.put(pluginClass.getName(), pd);

			PluginPackage pluginPackage = pd.getPluginPackage();
			List<PluginDescription> list =
				descriptionsByPackage.computeIfAbsent(pluginPackage, (k) -> new ArrayList<>());
			list.add(pd);
		}

	}

	public PluginDescription getPluginDescription(String className) {
		return descriptionsByName.get(className);
	}

	public void savePluginsToXml(Element root, List<Plugin> plugins) {
		Map<PluginPackage, List<Plugin>> pluginPackageMap = buildPluginPackageMap(plugins);
		for (PluginPackage pluginPackage : pluginPackageMap.keySet()) {
			root.addContent(getPackageElement(pluginPackage, pluginPackageMap.get(pluginPackage)));
		}
	}

	private Element getPackageElement(PluginPackage pluginPackage, List<Plugin> pluginList) {
		Element packageElement = new Element("PACKAGE");
		packageElement.setAttribute("NAME", pluginPackage.getName());
		List<PluginDescription> pluginDescriptions = descriptionsByPackage.get(pluginPackage);

		Set<String> includedPluginClasses = new HashSet<>();
		for (Plugin plugin : pluginList) {
			includedPluginClasses.add(plugin.getClass().getName());
		}

		// first loop through package looking for plugins to exclude.
		// 		plugins are excluded if they are "Released" or "Stable" and not currently in the tool
		//		In other words, these plugins are included by default and must be explicitly excluded
		//		if they are not to be in the tool

		for (PluginDescription pluginDescription : pluginDescriptions) {
			if (pluginDescription.getStatus() == PluginStatus.RELEASED) {
				String pluginClassName = pluginDescription.getPluginClass().getName();
				if (!includedPluginClasses.contains(pluginClassName)) {
					Element excludedPluginElement = new Element("EXCLUDE");
					excludedPluginElement.setAttribute("CLASS", pluginClassName);
					packageElement.addContent(excludedPluginElement);
				}
			}
		}

		// Now loop through the package looking for plugins to include.
		//   Plugins that are "Unstable" are not included by default, so if they exist in the
		//   tool, they must be explicitly included

		for (PluginDescription pluginDescription : pluginDescriptions) {
			if (pluginDescription.getStatus() != PluginStatus.RELEASED) {
				String pluginClassName = pluginDescription.getPluginClass().getName();
				if (includedPluginClasses.contains(pluginClassName)) {
					Element includedPluginElement = new Element("INCLUDE");
					includedPluginElement.setAttribute("CLASS", pluginClassName);
					packageElement.addContent(includedPluginElement);
				}
			}
		}

		return packageElement;
	}

	private Map<PluginPackage, List<Plugin>> buildPluginPackageMap(List<Plugin> plugins) {
		Map<PluginPackage, List<Plugin>> pluginPackageMap = new HashMap<>();
		for (Plugin plugin : plugins) {
			PluginDescription pluginDescription =
				descriptionsByName.get(plugin.getClass().getName());
			if (pluginDescription == null) {
				continue;
			}

			PluginPackage pluginPackage = pluginDescription.getPluginPackage();
			List<Plugin> list = pluginPackageMap.get(pluginPackage);
			if (list == null) {

				list = new ArrayList<>();
				pluginPackageMap.put(pluginPackage, list);
			}
			list.add(plugin);
		}
		return pluginPackageMap;
	}

	/**
	 * Used to convert an old style tool XML file by mapping the given class names to plugin
	 * packages and then adding <b>all</b> plugins in that package.  This has the effect of pulling
	 * in more plugin classes than were originally specified in the tool xml.
	 *
	 * @param classNames the list of classNames from from the old XML file
	 * @return the adjusted set of plugin class names
	 */
	public Set<String> getPluginNamesByCurrentPackage(List<String> classNames) {
		Set<PluginPackage> packages = new HashSet<>();
		Set<String> adjustedClassNames = new HashSet<>();

		for (String className : classNames) {
			PluginDescription pd = descriptionsByName.get(className);
			if (pd == null) {
				continue; // plugin no longer in tool
			}

			if (pd.getStatus() == PluginStatus.RELEASED) {
				packages.add(pd.getPluginPackage());
			}
			else {
				adjustedClassNames.add(className);
			}
		}

		for (PluginPackage pluginPackage : packages) {
			List<PluginDescription> packageDescriptions = descriptionsByPackage.get(pluginPackage);
			for (PluginDescription pd : packageDescriptions) {
				adjustedClassNames.add(pd.getPluginClass().getName());
			}
		}

		return adjustedClassNames;
	}

	public Set<String> getPluginClassNames(Element element) {

		Set<String> classNames = new HashSet<>();
		List<?> children = element.getChildren("PACKAGE");
		for (Object object : children) {

			Element child = (Element) object;
			String packageName = child.getAttributeValue("NAME");

			// classes excluded by name in the xml
			Set<String> excludedClasses = new HashSet<>();
			List<?> grandChildren = child.getChildren("EXCLUDE");
			for (Object obj : grandChildren) {
				Element grandChild = (Element) obj;
				String excludedClassName = grandChild.getAttributeValue("CLASS");
				excludedClasses.add(excludedClassName);
			}

			// classes included by name in the xml
			Set<String> includedClasses = new HashSet<>();
			grandChildren = child.getChildren("INCLUDE");
			for (Object obj : grandChildren) {
				Element grandChild = (Element) obj;
				String excludedClassName = grandChild.getAttributeValue("CLASS");
				includedClasses.add(excludedClassName);
			}

			if (!PluginPackage.exists(packageName)) {
				Msg.warn(this, "Unable to find plugin package '" + packageName +
					"' while restoring plugins from xml");
				continue;
			}

			PluginPackage pluginPackage = PluginPackage.getPluginPackage(packageName);
			List<PluginDescription> pluginDescriptionList =
				descriptionsByPackage.get(pluginPackage);
			if (pluginDescriptionList == null) {
				continue;
			}

			for (PluginDescription pluginDescription : pluginDescriptionList) {
				if (shouldAddPlugin(pluginDescription, includedClasses, excludedClasses)) {
					classNames.add(pluginDescription.getPluginClass().getName());
				}
			}
		}
		return classNames;

	}

	private boolean shouldAddPlugin(PluginDescription description, Set<String> include,
			Set<String> exclude) {

		String className = description.getPluginClass().getName();
		if (include.contains(className)) {
			return true;
		}
		if (exclude.contains(className)) {
			return false;
		}
		return description.getStatus() == PluginStatus.RELEASED;

	}

	public List<PluginPackage> getPluginPackages() {
		List<PluginPackage> list = new ArrayList<>(descriptionsByPackage.keySet());
		Collections.sort(list);
		return list;
	}

	public List<PluginDescription> getPluginDescriptions(PluginPackage pluginPackage) {
		List<PluginDescription> list = descriptionsByPackage.get(pluginPackage);
		List<PluginDescription> stableList = new ArrayList<>();
		for (PluginDescription pluginDescription : list) {
			if (pluginDescription.getStatus() == PluginStatus.UNSTABLE ||
				pluginDescription.getStatus() == PluginStatus.HIDDEN) {
				continue;
			}
			stableList.add(pluginDescription);
		}
		return stableList;
	}

	public List<PluginDescription> getUnstablePluginDescriptions() {
		List<PluginDescription> unstablePlugins = new ArrayList<>();
		for (PluginDescription pluginDescription : descriptionsByName.values()) {
			if (pluginDescription.getStatus() == PluginStatus.UNSTABLE) {
				unstablePlugins.add(pluginDescription);
			}
		}
		return unstablePlugins;
	}

	public List<PluginDescription> getManagedPluginDescriptions() {
		ArrayList<PluginDescription> nonHiddenPlugins = new ArrayList<>();
		for (PluginDescription pluginDescription : descriptionsByName.values()) {
			if (pluginDescription.getStatus() == PluginStatus.HIDDEN) {
				continue;
			}
			nonHiddenPlugins.add(pluginDescription);
		}
		return nonHiddenPlugins;
	}
}
