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

import java.lang.reflect.Method;
import java.net.URL;
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.Application;
import ghidra.framework.plugintool.*;
import ghidra.util.Msg;

/**
 * Class to hold meta information about a plugin, derived from meta-data attached to
 * each {@link Plugin} using a {@link PluginInfo @PluginInfo} annotation.
 */
public class PluginDescription implements Comparable<PluginDescription> {

	/**
	 * Fetches the {@link PluginDescription} for the specified Plugin class.
	 * <p>
	 * If the PluginDescription is found in the static cache, it is returned directly,
	 * otherwise a new instance is created (using annotation data attached to the Plugin
	 * class) and it is cached for later use.
	 *
	 * @param c Plugin's class
	 * @return {@link PluginDescription}
	 */
	public static PluginDescription getPluginDescription(Class<? extends Plugin> c) {
		// TODO: sync the hashmap?
		PluginDescription cachedPD =
			CACHE.computeIfAbsent(c, PluginDescription::createPluginDescription);
		return cachedPD;
	}

	private static HashMap<Class<? extends Plugin>, PluginDescription> CACHE = new HashMap<>();
	private static final String DOTCLASS_EXT = ".class";

	private final Class<? extends Plugin> pluginClass;
	private final String name;
	private final String shortDescription;
	private final String description;
	private final String category;
	private final PluginStatus status;
	private final PluginPackage pluginPackage;
	private final URL url;
	private final boolean isSlowInstallation;
	private String moduleName; // lazy loaded
	private final List<Class<?>> servicesRequired;
	private final List<Class<?>> servicesProvided;
	private final List<Class<? extends PluginEvent>> eventsConsumed;
	private final List<Class<? extends PluginEvent>> eventsProduced;

	private PluginDescription(Class<? extends Plugin> pluginClass, String pluginPackageName,
			String category, String shortDescription, String description, PluginStatus status,
			boolean isSlowInstallation, List<Class<?>> servicesRequired,
			List<Class<?>> servicesProvided, List<Class<? extends PluginEvent>> eventsConsumed,
			List<Class<? extends PluginEvent>> eventsProduced) {

		this.pluginClass = pluginClass;
		this.name = pluginClass.getSimpleName();
		this.pluginPackage = PluginPackage.getPluginPackage(pluginPackageName);
		this.category = category;
		this.shortDescription = (shortDescription == null) ? "no description" : shortDescription;
		this.status = status;
		this.description = (description == null) ? this.shortDescription : description;
		this.isSlowInstallation = isSlowInstallation;

		String pathName = pluginClass.getName().replace('.', '/') + DOTCLASS_EXT;
		this.url = pluginClass.getClassLoader().getResource(pathName);

		this.servicesRequired = servicesRequired;
		this.servicesProvided = servicesProvided;

		this.eventsConsumed = eventsConsumed;
		this.eventsProduced = eventsProduced;
	}

	/**
	 * Returns true if this plugin requires a noticeable amount of time to load when installed.
	 * @return
	 */
	public boolean isSlowInstallation() {
		return isSlowInstallation;
	}

	/**
	 * Set the short description for what the plugin does.
	 * @return short description
	 */
	public String getShortDescription() {
		return shortDescription;
	}

	/**
	 * Get the location for the source file for the plugin.
	 * @return path to the source file
	 */
	public String getSourceLocation() {
		String path = url.getFile();
		if ("jar".equals(url.getProtocol())) {
			int i = path.indexOf('!');
			if (i >= 0) {
				path = path.substring(0, i);
			}
			String fileProtoPrefix = "file:";
			if (path.startsWith(fileProtoPrefix)) {
				path = path.substring(fileProtoPrefix.length() + 1);
			}
			return path;
		}
		String classpath = pluginClass.getName();
		path = path.substring(0, path.length() - classpath.length() - DOTCLASS_EXT.length() - 1);
		return path;
	}

	/**
	 * Return whether the plugin is in the given category.
	 * @param parentCategory category to check
	 * @return true if the plugin is in the category
	 */
	public boolean isInCategory(String parentCategory) {
		return parentCategory.equals(category);
	}

	/**
	 * Return the name of the plugin.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Return the type for the plugin: CORE, CONTRIB, PROTOTYPE, or
	 * DEVELOP. Within a type, plugins are grouped by category.
	 * @return the type (or null if there is no module)
	 */
	public String getModuleName() {
		if (moduleName == null) {
			ResourceFile moduleRootDirectory = Application.getMyModuleRootDirectory();
			moduleName = (moduleRootDirectory == null) ? null : moduleRootDirectory.getName();
		}

		return moduleName;
	}

	/**
	 * Return the class of the plugin.
	 * @return plugin class object
	 */
	public Class<? extends Plugin> getPluginClass() {
		return pluginClass;
	}

	/**
	 * Return the description of the plugin.
	 * @return {@code "<None>"} if no description was specified
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Return the category for the plugin.
	 * @return the category
	 */
	public String getCategory() {
		return category;
	}

	/**
	 * Returns the development status of the plugin.
	 */
	public PluginStatus getStatus() {
		return status;
	}

	public PluginPackage getPluginPackage() {
		return pluginPackage;

	}

	public List<Class<?>> getServicesRequired() {
		return servicesRequired;
	}

	public List<Class<?>> getServicesProvided() {
		return servicesProvided;
	}

	public List<Class<? extends PluginEvent>> getEventsConsumed() {
		return eventsConsumed;
	}

	public List<Class<? extends PluginEvent>> getEventsProduced() {
		return eventsProduced;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((pluginClass == null) ? 0 : pluginClass.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof PluginDescription)) {
			return false;
		}
		PluginDescription other = (PluginDescription) obj;
		if (pluginClass == null) {
			if (other.pluginClass != null) {
				return false;
			}
		}
		else if (!pluginClass.equals(other.pluginClass)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return pluginPackage + ":" + category + ":" + name;
	}

	@Override
	public int compareTo(PluginDescription other) {
		return name.compareTo(other.name);
	}

	//-------------------------------------------------------------------------------------
	// static methods that we don't care about
	//-------------------------------------------------------------------------------------

	/**
	 * Constructs a new PluginDescription for the given plugin class.
	 * <p>
	 * Deprecated, use {@link PluginInfo @PluginInfo} instead.
	 *
	 * @param pluginClass the class of the plugin
	 * @param status the status, UNSTABLE, STABLE, RELEASED, DEBUG, or EXAMPLE
	 * @param pluginPackage the package to which the plugin belongs (see {@link PluginPackage}
	 *        subclasses for examples)
	 * @param category the category to which the plugin belongs (see {@link PluginCategoryNames}
	 * @param shortDescription a brief description of what the plugin does
	 * @param description the long description of what the plugin does
	 * @return the new (or cached) PluginDescription
	 */
	@Deprecated
	public static PluginDescription createPluginDescription(Class<?> pluginClass,
			PluginStatus status, String pluginPackage, String category, String shortDescription,
			String description) {

		PluginDescription pd = createPluginDescription(pluginClass, status, pluginPackage, category,
			shortDescription, description, false);
		return pd;
	}

	/**
	 * Constructs a new PluginDescription for the given plugin class.
	 * <p>
	 * @deprecated, use {@link PluginInfo &#64;PluginInfo} instead.
	 *
	 * @param pluginClassParam the class of the plugin
	 * @param status the status, UNSTABLE, STABLE, RELEASED, DEBUG, or EXAMPLE
	 * @param pluginPackage the package to which the plugin belongs (see {@link PluginPackage}
	 *        subclasses for examples)
	 * @param category the category to which the plugin belongs (see {@link PluginCategoryNames}
	 * @param shortDescription a brief description of what the plugin does
	 * @param description the long description of what the plugin does
	 * @param isSlowInstallation true signals that this plugin loads slowly
	 * @return the new (or cached) PluginDescription
	 */
	@Deprecated
	public static PluginDescription createPluginDescription(Class<?> pluginClassParam,
			PluginStatus status, String pluginPackage, String category, String shortDescription,
			String description, boolean isSlowInstallation) {

		if (!Plugin.class.isAssignableFrom(pluginClassParam)) {
			throw new IllegalArgumentException("Bad Plugin class type: " + pluginClassParam);
		}
		@SuppressWarnings("unchecked")
		Class<? extends Plugin> pluginClass = (Class<? extends Plugin>) pluginClassParam;

		return new PluginDescription(pluginClass, pluginPackage, category, shortDescription,
			description, status, isSlowInstallation, Collections.emptyList(),
			Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
	}

	/**
	 * Creates a new {@link PluginDescription} for the specified Plugin class.
	 *
	 * @param c Plugin's class
	 * @return new {@link PluginDescription}
	 */
	private static PluginDescription createPluginDescription(Class<? extends Plugin> c) {
		PluginDescription pd = createPluginDescriptionFromAnnotation(c);
		if (pd == null) {
			pd = createPluginDescriptionFromDeprecatedStaticMethod(c);
		}
		return (pd != null) ? pd : createDefaultPluginDescription(c);
	}

	/**
	 * Creates a {@link PluginDescription} using information gathered from annotations
	 * present on the specified {@link Plugin}'s class.
	 *
	 * @param c Plugin's class
	 * @return new {@link PluginDescription} or null if no annotation info available
	 */
	private static PluginDescription createPluginDescriptionFromAnnotation(
			Class<? extends Plugin> c) {
		PluginInfo pia = c.getAnnotation(PluginInfo.class);
		return (pia != null) ? new PluginDescription(c, pia.packageName(), pia.category(),
			pia.shortDescription(), pia.description(), pia.status(), pia.isSlowInstallation(),
			Arrays.asList(pia.servicesRequired()), Arrays.asList(pia.servicesProvided()),
			Arrays.asList(pia.eventsConsumed()), Arrays.asList(pia.eventsProduced())) : null;
	}

	@Deprecated
	private static PluginDescription createPluginDescriptionFromDeprecatedStaticMethod(
			Class<? extends Plugin> pluginClass) {
		try {
			Method method = pluginClass.getMethod("getPluginDescription", Class.class);
			if (method.getReturnType() == PluginDescription.class) {
				return (PluginDescription) method.invoke(null, pluginClass);
			}
			Msg.debug(PluginDescription.class,
				"Bad return type for getPluginDescription in " + pluginClass.getName());
		}
		catch (Throwable e) {
			Msg.debug(PluginDescription.class, "Error getting plugin description for " +
				pluginClass.getName() + ": " + e.getMessage());
		}

		return null;
	}

	/**
	 * Creates an empty place-holder {@link PluginDescription} for the specified class.
	 *
	 * @param c Plugin's class
	 * @return new {@link PluginDescription} with place-holder values.
	 */
	private static PluginDescription createDefaultPluginDescription(Class<? extends Plugin> c) {
		return new PluginDescription(c, MiscellaneousPluginPackage.NAME,
			PluginCategoryNames.UNMANAGED, null, null, PluginStatus.UNSTABLE, false,
			Collections.emptyList(), Collections.emptyList(), Collections.emptyList(),
			Collections.emptyList());
	}

}
