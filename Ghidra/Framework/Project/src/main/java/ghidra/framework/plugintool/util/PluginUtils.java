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

import java.lang.reflect.*;
import java.util.List;

import ghidra.framework.plugintool.*;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.AssertException;

/**
 * Utility class for plugin-related methods.
 *
 */
public class PluginUtils {

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

			List<Class<? extends Plugin>> classes = ClassSearcher.getClasses(Plugin.class);
			for (Class<? extends Plugin> plug : classes) {
				if (plug.getName().equals(pluginClassName)) {
					return plug;
				}
			}

			Class<?> tmpClass = Class.forName(pluginClassName);
			if (!Plugin.class.isAssignableFrom(tmpClass)) {
				throw new PluginException(
					"Class " + pluginClassName + " is not derived from Plugin");
			}
			return tmpClass.asSubclass(Plugin.class);
		}
		catch (ClassNotFoundException e) {
			throw new PluginException("Plugin class not found: " + pluginClassName);
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
}
