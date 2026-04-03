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

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.jdom2.Element;

import ghidra.util.NumericUtilities;
import ghidra.util.Swing;
import ghidra.util.xml.XmlUtilities;

/**
 * A class to manage saving and restoring of known extension used by a tool.
 */
class ToolExtensionsStatusManager {

	private static final String XML_TAG_EXTENSIONS = "EXTENSIONS";
	private static final String XML_TAG_EXTENSION = "EXTENSION";
	private static final String XML_TAG_PLUGIN = "PLUGIN";
	private static final String XML_ATTR_EXTENSION_NAME_ENCODED = "ENCODED_NAME";
	private static final String XML_ATTR_EXTENSION_NAME = "NAME";
	private static final String XML_ATTR_EXTENSION_PLUGIN_CLASS = "CLASS";

	private Set<Class<?>> newExtensionPlugins = new HashSet<>();
	private ExtensionsEnabledState extensionsState;

	ToolExtensionsStatusManager(ExtensionsEnabledState extensionState) {
		this.extensionsState = extensionState;
	}

	void checkForNewExtensions() {
		if (newExtensionPlugins.isEmpty()) {
			return;
		}

		// Run later to not block the opening of the tool.
		Swing.runLater(() -> {
			extensionsState.propmtToConfigureNewPlugins(newExtensionPlugins);
			newExtensionPlugins.clear();
		});
	}

	void saveToXml(Element xml) {

		Map<String, Set<Class<?>>> pluginsByExtension =
			extensionsState.getAllKnownExtensions();
		Element extensionsParent = new Element(XML_TAG_EXTENSIONS);

		Set<Entry<String, Set<Class<?>>>> entries = pluginsByExtension.entrySet();
		for (Entry<String, Set<Class<?>>> entry : entries) {
			String name = entry.getKey();

			Element extensionsElement = new Element(XML_TAG_EXTENSION);
			setExtensionName(extensionsElement, name);
			extensionsParent.addContent(extensionsElement);

			Set<Class<?>> plugins = entry.getValue();
			for (Class<?> clazz : plugins) {
				String className = clazz.getName();
				Element pluginElement = new Element(XML_TAG_PLUGIN);
				pluginElement.setAttribute(XML_ATTR_EXTENSION_PLUGIN_CLASS, className);
				extensionsElement.addContent(pluginElement);
			}
		}

		xml.addContent(extensionsParent);
	}

	void restoreFromXml(Element xml) {

		/*
		 	1) Grab all extension plugins currently found on the classpath.  This will include all 
		 	   old and new extensions.
		 	 
		 	2) Grab all previously known extensions and plugins.
		 	
		 	3) Find all entirely new extensions or extensions that have new plugins added.
		 	
		 	4) Filter plugins by those already installed.  
		 	
		 	5) Save the new extension plugins for later user prompting when saving to xml.
		 */
		Map<String, Set<Class<?>>> extensionPlugins = extensionsState.getAllKnownExtensions();
		Map<String, ExtensionMemento> xmlMementosByName = getKnownExtensions(xml);
		Set<String> names = extensionPlugins.keySet();
		Set<String> newExtensions = new HashSet<>(names);
		for (String name : names) {
			ExtensionMemento xmlMemento = xmlMementosByName.get(name);
			if (xmlMemento == null) {
				continue; // new extension
			}

			// The extension is known.  If it doesn't have new plugins, then we can remove it from 
			// the new extensions, assuming it has not changed.
			if (!hasNewPlugins(xmlMemento, extensionPlugins)) {
				newExtensions.remove(name);
			}
		}

		Set<Class<?>> newPlugins = newExtensions.stream()
				.map(name -> extensionPlugins.get(name)) // classes by extension name
				.flatMap(set -> set.stream())		     // map all sets to a single stream
				.collect(Collectors.toSet());

		extensionsState.removeInstalledPlugins(newPlugins);

		// Get all plugins contained in the 'new' extensions. If there are none, then 
		// either none of the extensions has any plugins, or Ghidra hasn't been restarted since 
		// installing the extension(s), so none of the plugin classes have been loaded.
		newExtensionPlugins.addAll(newPlugins);
	}

	private static boolean hasNewPlugins(ExtensionMemento xmlMemento,
			Map<String, Set<Class<?>>> pluginsByExtensionName) {

		// If the xml memento is empty, it is either the old style xml that did not save plugin 
		// names or is the new style xml, but the extension did not previously have any plugins. In
		// this case, we want to prompt the user if there are plugins to install.
		Set<String> xmlClassNames = xmlMemento.pluginClassNames();
		Set<Class<?>> cpPluginClasses = pluginsByExtensionName.get(xmlMemento.name());
		if (xmlClassNames.isEmpty() && !cpPluginClasses.isEmpty()) {
			return true;
		}

		List<String> cpNames = cpPluginClasses.stream()
				.map(c -> c.getName())
				.collect(Collectors.toList());

		cpNames.removeAll(xmlClassNames);
		return !cpNames.isEmpty();
	}

	private static Map<String, ExtensionMemento> getKnownExtensions(Element xml) {

		Set<ExtensionMemento> mementos = new HashSet<>();
		Element extensionsParent = xml.getChild(XML_TAG_EXTENSIONS);
		if (extensionsParent == null) {
			return Map.of();
		}

		for (Element child : extensionsParent.getChildren(XML_TAG_EXTENSION)) {
			List<Element> plugins = child.getChildren(XML_TAG_PLUGIN);
			Set<String> pluginClasses = getExtensionPluginClasses(plugins);
			String extensionName = readExtensionName(child);
			mementos.add(new ExtensionMemento(extensionName, pluginClasses));
		}

		return mementos.stream()
				.collect(Collectors.toMap(
					ExtensionMemento::name,
					Function.identity()));
	}

	private static Set<String> getExtensionPluginClasses(List<Element> plugins) {
		Set<String> pluginNames = new HashSet<>();
		for (Element element : plugins) {
			String className = element.getAttributeValue(XML_ATTR_EXTENSION_PLUGIN_CLASS);
			pluginNames.add(className);
		}
		return pluginNames;
	}

	private static String readExtensionName(Element element) {
		String encodedValue = element.getAttributeValue(XML_ATTR_EXTENSION_NAME_ENCODED);
		if (encodedValue != null) {
			byte[] bytes = NumericUtilities.convertStringToBytes(encodedValue);
			return new String(bytes, StandardCharsets.UTF_8);
		}
		return element.getAttributeValue(XML_ATTR_EXTENSION_NAME);
	}

	private static void setExtensionName(Element element, String name) {
		if (XmlUtilities.hasInvalidXMLCharacters(name)) {
			element.setAttribute(XML_ATTR_EXTENSION_NAME_ENCODED, NumericUtilities
					.convertBytesToString(name.getBytes(StandardCharsets.UTF_8)));
		}
		else {
			element.setAttribute(XML_ATTR_EXTENSION_NAME, name);
		}
	}

	private static record ExtensionMemento(String name, Set<String> pluginClassNames) {

	}
}
