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

import java.util.*;
import java.util.function.Predicate;

import org.jdom.Element;

import ghidra.framework.main.ProgramaticUseOnly;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;

public class PluginClassManager {

	private Map<PluginPackage, List<PluginDescription>> packageMap = new HashMap<>();

	private Map<String, PluginDescription> pluginClassMap = new HashMap<>();

	public PluginClassManager(Class<?> filterClass, Class<?> exclusionClass) {
		populatePluginDescriptionMaps(filterClass, exclusionClass);

	}

	public PluginDescription getPluginDescription(String className) {
		return pluginClassMap.get(className);
	}

	private void populatePluginDescriptionMaps(Class<?> localFilterClass,
			Class<?> localExclusionClass) {

		Predicate<Class<? extends Plugin>> myClassFilter =
			c -> (localFilterClass == null || localFilterClass.isAssignableFrom(c)) &&
				(localExclusionClass == null || !localExclusionClass.isAssignableFrom(c)) &&
				!ProgramaticUseOnly.class.isAssignableFrom(c);

		List<Class<? extends Plugin>> classes =
			ClassSearcher.getClasses(Plugin.class, myClassFilter);

		for (Class<? extends Plugin> pluginClass : classes) {
			if (!PluginUtils.isValidPluginClass(pluginClass)) {
				Msg.warn(this, "Plugin does not have valid constructor! Skipping " + pluginClass);
				continue;
			}

			PluginDescription pd = PluginDescription.getPluginDescription(pluginClass);
			pluginClassMap.put(pluginClass.getName(), pd);

			PluginPackage pluginPackage = pd.getPluginPackage();
			List<PluginDescription> list =
				packageMap.computeIfAbsent(pluginPackage, (k) -> new ArrayList<>());
			list.add(pd);
		}
	}

	public void addXmlElementsForPlugins(Element root, List<Plugin> plugins) {
		Map<PluginPackage, List<Plugin>> pluginPackageMap = buildPluginPackageMap(plugins);
		for (PluginPackage pluginPackage : pluginPackageMap.keySet()) {
			root.addContent(getPackageElement(pluginPackage, pluginPackageMap.get(pluginPackage)));
		}
	}

	private Element getPackageElement(PluginPackage pluginPackage, List<Plugin> pluginList) {
		Element packageElement = new Element("PACKAGE");
		packageElement.setAttribute("NAME", pluginPackage.getName());
		List<PluginDescription> pluginDescriptions = packageMap.get(pluginPackage);

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
			PluginDescription pluginDescription = pluginClassMap.get(plugin.getClass().getName());
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
	 * Used to convert an old style tool XML file by adding in classes in the same packages as
	 * those that were names specifically in the XML file
	 * @param classNames the list of classNames from from the old XML file
	 * @return
	 */
	public List<String> fillInPackageClasses(List<String> classNames) {
		Set<PluginPackage> packages = new HashSet<>();
		Set<String> adjustedClassNames = new HashSet<>();

		for (String className : classNames) {
			PluginDescription pluginDescription = pluginClassMap.get(className);
			if (pluginDescription != null) {
				if (pluginDescription.getStatus() == PluginStatus.RELEASED) {
					packages.add(pluginDescription.getPluginPackage());
				}
				else {
					adjustedClassNames.add(className);
				}
			}
		}
		for (PluginPackage pluginPackage : packages) {
			List<PluginDescription> list = packageMap.get(pluginPackage);
			for (PluginDescription pluginDescription : list) {
				if (pluginDescription.getStatus() != PluginStatus.RELEASED) {
					continue;
				}
				String name = pluginDescription.getPluginClass().getName();
				adjustedClassNames.add(name);
			}
		}

		return new ArrayList<>(adjustedClassNames);
	}

	public List<String> getPluginClasses(Element element) {
		List<String> classNames = new ArrayList<>();

		List<?> children = element.getChildren("PACKAGE");
		for (Object object : children) {
			Element child = (Element) object;
			Set<String> excludedClasses = new HashSet<>();
			List<?> grandChildren = child.getChildren("EXCLUDE");
			for (Object obj : grandChildren) {
				Element grandChild = (Element) obj;
				String excludedClassName = grandChild.getAttributeValue("CLASS");
				excludedClasses.add(excludedClassName);
			}
			Set<String> includedClasses = new HashSet<>();
			grandChildren = child.getChildren("INCLUDE");
			for (Object obj : grandChildren) {
				Element grandChild = (Element) obj;
				String excludedClassName = grandChild.getAttributeValue("CLASS");
				includedClasses.add(excludedClassName);
			}

			String packageName = child.getAttributeValue("NAME");
			PluginPackage pluginPackage = PluginPackage.getPluginPackage(packageName);
			List<PluginDescription> pluginDescriptionList = packageMap.get(pluginPackage);
			if (pluginDescriptionList == null) {
				continue;
			}
			for (PluginDescription pluginDescription : pluginDescriptionList) {
				String pluginClass = pluginDescription.getPluginClass().getName();
				if (pluginDescription.getStatus() == PluginStatus.RELEASED) {
					if (!excludedClasses.contains(pluginClass)) {
						classNames.add(pluginClass);
					}
				}
				else {
					if (includedClasses.contains(pluginClass)) {
						classNames.add(pluginClass);
					}
				}
			}
		}
		return classNames;
	}

	public List<PluginPackage> getPluginPackages() {
		List<PluginPackage> list = new ArrayList<>(packageMap.keySet());
		Collections.sort(list);
		return list;
	}

	public List<PluginDescription> getReleasedPluginDescriptions(PluginPackage pluginPackage) {
		List<PluginDescription> list = packageMap.get(pluginPackage);
		List<PluginDescription> stableList = new ArrayList<>();
		for (PluginDescription pluginDescription : list) {
			if (pluginDescription.getStatus() == PluginStatus.RELEASED) {
				stableList.add(pluginDescription);
			}
		}
		return stableList;
	}

	public List<PluginDescription> getNonReleasedPluginDescriptions() {
		List<PluginDescription> unstablePlugins = new ArrayList<>();
		for (PluginDescription pluginDescription : pluginClassMap.values()) {
			if (pluginDescription.getStatus() == PluginStatus.HIDDEN ||
				pluginDescription.getStatus() == PluginStatus.RELEASED) {
				continue;
			}
			unstablePlugins.add(pluginDescription);
		}
		return unstablePlugins;
	}

	public List<PluginDescription> getAllPluginDescriptions() {
		ArrayList<PluginDescription> nonHiddenPlugins = new ArrayList<>();
		for (PluginDescription pluginDescription : pluginClassMap.values()) {
			if (pluginDescription.getStatus() == PluginStatus.HIDDEN) {
				continue;
			}
			nonHiddenPlugins.add(pluginDescription);
		}
		return nonHiddenPlugins;
	}
}
