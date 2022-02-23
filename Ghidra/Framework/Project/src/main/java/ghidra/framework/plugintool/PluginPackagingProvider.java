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

import javax.swing.Icon;

import ghidra.framework.plugintool.util.*;
import resources.ResourceManager;

/**
 * Provides {@link PluginPackage}s and plugin descriptions and to clients
 */
public interface PluginPackagingProvider {

	public static final Icon EXPERIMENTAL_ICON =
		ResourceManager.loadImage("images/applications-science.png");
	public static final PluginPackage UNSTABLE_PACKAGE = new PluginPackage("Experimental",
		EXPERIMENTAL_ICON,
		"This package contains plugins that are not fully tested and/or documented." +
			"You must add these plugins individually.  Adding these plugins could cause the tool" +
			" to become unstable.",
		Integer.MAX_VALUE) {
		//
	};

	/**
	 * Returns all known plugin packages
	 * @return the plugin packages
	 */
	public List<PluginPackage> getPluginPackages();

	/**
	 * Returns all loaded plugin descriptions
	 * @return the descriptions
	 */
	public List<PluginDescription> getPluginDescriptions();

	/**
	 * Returns the plugin description for the given plugin class name
	 * @param pluginClassName the plugin class name
	 * @return the description
	 */
	public PluginDescription getPluginDescription(String pluginClassName);

	/**
	 * Get all plugin descriptions for the given plugin package
	 * @param pluginPackage the package
	 * @return the descriptions
	 */
	public List<PluginDescription> getPluginDescriptions(PluginPackage pluginPackage);

	/**
	 * Returns the plugin package used to house all unstable plugin packages
	 * @return the package
	 */
	public PluginPackage getUnstablePluginPackage();

	/**
	 * Returns all {@link PluginStatus#UNSTABLE} plugin package descriptions
	 * @return the descriptions
	 */
	public List<PluginDescription> getUnstablePluginDescriptions();
}
