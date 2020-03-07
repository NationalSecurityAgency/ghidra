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

import java.io.File;
import java.lang.reflect.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.dialog.ExtensionDetails;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.AssertException;

/**
 * Utility class for plugin-related methods.
 *
 */
public class PluginUtils {

	/**
	 * Finds all {@link PluginDescription} objects that match a given set of plugin classes. This
	 * effectively tells the caller which of the given plugins have been loaded by the class loader.
	 * <p>
	 * eg: If the list of plugin classes contains the class "FooPlugin.class", this method
	 * will search the {@link PluginConfigurationModel} for any plugin with the name "FooPlugin" and
	 * return its {@link PluginDescription}.
	 * <p>
	 * Note that this method does not take path/package information into account when finding
	 * plugins; in the example above, if there is more than one plugin with the name "FooPlugin",
	 * only one will be found (the one found is not guaranteed to be the first).
	 *
	 * @param tool the current tool
	 * @param plugins the list of plugin classes to search for
	 * @return list of plugin descriptions
	 */
	public static List<PluginDescription> getPluginDescriptions(PluginTool tool,
			List<Class<?>> plugins) {

		// First define the list of plugin descriptions to return.
		List<PluginDescription> retPlugins = new ArrayList<>();

		// Get all plugins that have been loaded.
		PluginConfigurationModel model = new PluginConfigurationModel(tool, null);
		List<PluginDescription> allPluginDescriptions = model.getAllPluginDescriptions();

		// For each plugin classes we're searching for, see if an entry exists in the list of all
		// loaded plugins.
		for (Class<?> plugin : plugins) {
			String pluginName = plugin.getSimpleName();

			Optional<PluginDescription> desc = allPluginDescriptions.stream().filter(
				d -> (pluginName.equals(d.getName()))).findAny();
			if (desc.isPresent()) {
				retPlugins.add(desc.get());
			}
		}

		return retPlugins;
	}

	/**
	 * Finds all plugin classes loaded from a given set of extensions.
	 *
	 * @param extensions set of extensions to search
	 * @return list of loaded plugin classes, or empty list if none found
	 */
	public static List<Class<?>> findLoadedPlugins(Set<ExtensionDetails> extensions) {

		List<Class<?>> pluginClasses = new ArrayList<>();
		for (ExtensionDetails extension : extensions) {

			if (extension == null || extension.getInstallPath() == null) {
				continue;
			}

			List<Class<?>> classes = findLoadedPlugins(new File(extension.getInstallPath()));
			pluginClasses.addAll(classes);
		}

		return pluginClasses;
	}

	/**
	 * Finds all plugin classes loaded from a particular folder/file.
	 * <p>
	 * This uses the {@link ClassSearcher} to find all <code>Plugin.class</code> objects on the
	 * classpath. For each class, the original resource file is compared against the
	 * given folder and if it's contained therein (or if it matches a given jar), it's
	 * added to the return list.
	 *
	 * @param dir the directory to search, or a jar file
	 * @return list of {@link Plugin} classes, or empty list if none found
	 */
	private static List<Class<?>> findLoadedPlugins(File dir) {

		// The list of classes to return.
		List<Class<?>> retPlugins = new ArrayList<>();

		// Find any jar files in the directory provided. Our plugin(s) will always be
		// in a jar.
		List<File> jarFiles = new ArrayList<>();
		findJarFiles(dir, jarFiles);

		// Now get all Plugin.class files that have been loaded, and see if any of them
		// were loaded from one of the jars we just found.
		List<Class<? extends Plugin>> plugins = ClassSearcher.getClasses(Plugin.class);
		for (Class<? extends Plugin> plugin : plugins) {
			URL location = plugin.getResource('/' + plugin.getName().replace('.', '/') + ".class");
			if (location == null) {
				Msg.warn(null, "Class location for plugin [" + plugin.getName() +
					"] could not be determined.");
				continue;
			}
			String pluginLocation = location.getPath();
			for (File jar : jarFiles) {
				URL jarUrl = null;
				try {
					jarUrl = jar.toURI().toURL();
					if (pluginLocation.contains(jarUrl.getPath())) {
						retPlugins.add(plugin);
					}
				}
				catch (MalformedURLException e) {
					continue;
				}
			}
		}
		return retPlugins;
	}

	/**
	 * Populates the given list with all discovered jar files found in the given directory and
	 * its subdirectories.
	 *
	 * @param dir the directory to search
	 * @param jarFiles list of found jar files
	 */
	private static void findJarFiles(File dir, List<File> jarFiles) {
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

	/**
	 * Returns a new instance of a {@link Plugin}.
	 *
	 * @param pluginClass Specific Plugin Class
	 * @param tool The {@link PluginTool} that is the parent of the new Plugin
	 * @return a new Plugin instance, never NULL.
	 * @throws PluginException if problem constructing the Plugin instance.
	 */
	public static <T extends Plugin> T instantiatePlugin(Class<T> pluginClass, PluginTool tool)
			throws PluginException {
		String className = pluginClass.getName();
		try {
			Constructor<T> ctor = pluginClass.getConstructor(PluginTool.class);
			ctor.setAccessible(true);
			return ctor.newInstance(tool);
		}
		catch (NoSuchMethodException e) {
			throw new PluginException(className, "Possibly missing plugin constructor");
		}
		catch (InvocationTargetException e) {
			Throwable t = e.getCause();

			// Protect against dereferencing the getCause call above, which may return null.
			String message = t == null ? "" : t.getMessage();

			Msg.error(PluginUtils.class, "Unexpected Exception: " + message, t);
			throw new PluginException("Error constructing plugin: " + pluginClass, e);

		}
		catch (InstantiationException e) {
			throw new PluginException(className, "Could not instantiate plugin class " + e);

		}
		catch (IllegalAccessException e) {
			throw new PluginException(className,
				"Illegal Access exception, make sure plugin class and constructor is public");
		}
	}

	/**
	 * Returns the Class for a Plugin, by class name.
	 *
	 * @param pluginClassName String class name
	 * @return Class that is a Plugin, never null.
	 * @throws PluginException if specified class does not exist or is not a Plugin.
	 */
	public static Class<? extends Plugin> forName(String pluginClassName) throws PluginException {
		try {
			Class<?> tmpClass = Class.forName(pluginClassName);
			if (!Plugin.class.isAssignableFrom(tmpClass)) {
				throw new PluginException(
					"Class " + pluginClassName + " is not derived from Plugin");
			}
			return tmpClass.asSubclass(Plugin.class);
		}
		catch (ClassNotFoundException e) {
			throw new PluginException("Plugin class not found");
		}
	}

	private static String getStaticStringFieldValue(Class<?> clazz, String fieldName) {
		try {
			Field field = clazz.getField(fieldName);
			return (String) field.get(null);
		}
		catch (NoSuchFieldException ex) {
			// ignore
		}
		catch (IllegalAccessException ex) {
			throw new AssertException(
				"default provider class for " + clazz.getName() + " is not declared to be public!");
		}
		return null;
	}

	/**
	 * Returns the Plugin Class that is specified as being the defaultProvider for a
	 * Service, or null if no default provider is specified.
	 * <p>
	 * @param serviceClass Service interface class
	 * @return Plugin class that provides the specified service
	 */
	public static Class<? extends Plugin> getDefaultProviderForServiceClass(Class<?> serviceClass) {
		String defaultProviderClassName = null;
		ServiceInfo sia = serviceClass.getAnnotation(ServiceInfo.class);
		if (sia != null) {
			if (sia.defaultProvider().length > 0) {
				return sia.defaultProvider()[0];
			}
			defaultProviderClassName = sia.defaultProviderName().trim();
		}
		if (defaultProviderClassName == null || defaultProviderClassName.isEmpty()) {
			defaultProviderClassName =
				PluginUtils.getStaticStringFieldValue(serviceClass, "defaultProvider");
		}
		if (defaultProviderClassName != null) {
			try {
				Class<?> tmpClass = Class.forName(defaultProviderClassName);
				return tmpClass.asSubclass(Plugin.class);
			}
			catch (ClassCastException cce) {
				Msg.error(PluginUtils.class,
					"The default provider specified for service " + serviceClass.getName() + " (" +
						defaultProviderClassName + ") is not a Plugin!");
			}
			catch (ClassNotFoundException e) {
				throw new AssertException(
					"default provider class for " + serviceClass.getName() + " not found!");

			}
		}
		return null;
	}

	/**
	 * Returns the name of a Plugin based on its class.
	 *
	 * @param pluginClass Class to get name from
	 * @return String name, based on Class's getSimpleName()
	 */
	public static String getPluginNameFromClass(Class<? extends Plugin> pluginClass) {
		return pluginClass.getSimpleName();
	}

	/**
	 * Ensures the specified Plugin has a unique name among all Plugin classes
	 * found in the current ClassSearcher's reach.
	 *
	 * @param pluginClass Class
	 * @throws PluginException throws exception if Plugin class is not uniquely named
	 */
	public static void assertUniquePluginName(Class<? extends Plugin> pluginClass)
			throws PluginException {
		String pluginName = getPluginNameFromClass(pluginClass);
		for (Class<? extends Plugin> otherPluginClass : ClassSearcher.getClasses(Plugin.class)) {
			if (otherPluginClass != pluginClass &&
				getPluginNameFromClass(otherPluginClass).equals(pluginName)) {
				throw new PluginException("Duplicate Plugin name: " + pluginClass.getName() +
					" and " + otherPluginClass.getName());
			}
		}
	}

	/**
	 * Returns true if the specified Plugin class is well-formed and meets requirements for
	 * Ghidra Plugins:
	 * <ul>
	 * 	<li>Has a constructor with a signature of <code>ThePlugin(PluginTool tool)</code>
	 * 	<li>Has a {@link PluginInfo @PluginInfo} annotation.
	 * </ul>
	 * <p>
	 * See {@link Plugin}.
	 * <p>
	 * @param pluginClass Class to examine.
	 * @return boolean true if well formed.
	 */
	public static boolean isValidPluginClass(Class<? extends Plugin> pluginClass) {
		try {
			// will throw exception if missing ctor
			pluginClass.getConstructor(PluginTool.class);

//		#if ( can_do_strict_checking )
//			PluginInfo pia = pluginClass.getAnnotation(PluginInfo.class);
//			return pia != null;
//		#else
			// for now
			return true;
//			#endif
		}
		catch (NoSuchMethodException e) {
			// no matching constructor method
		}
		return false;

	}
}
