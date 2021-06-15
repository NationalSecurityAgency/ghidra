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
package ghidra.framework.preferences;

import java.io.*;
import java.util.*;

import ghidra.framework.Application;
import ghidra.framework.GenericRunInfo;
import ghidra.util.Msg;
import util.CollectionUtils;
import utilities.util.FileUtilities;

/**
 * Uses Properties to manage user preferences as name/value pairs.  All methods
 * are static.
 */
public class Preferences {
	/**
	 * The <code>APPLICATION_PREFERENCES_FILENAME</code> is the default name for the user preferences file.
	 * @see ghidra.framework.preferences.Preferences
	 */
	public static final String APPLICATION_PREFERENCES_FILENAME = "preferences";

	/**
	 * Preference name of the user plugin path.
	 */
	private final static String USER_PLUGIN_PATH = "UserPluginPath";

	/**
	 * Preference name for the last opened archive directory.
	 */
	public static final String LAST_OPENED_ARCHIVE_DIRECTORY = "LastOpenedArchiveDirectory";

	/**
	 * Preference name for the project directory.
	 */
	public final static String PROJECT_DIRECTORY = "ProjectDirectory";

	/**
	 * Preference name for import directory that was last accessed for tools.
	 */
	public final static String LAST_TOOL_IMPORT_DIRECTORY = "LastToolImportDirectory";
	/**
	 * Preference name for export directory that was last accessed for tools.
	 */
	public final static String LAST_TOOL_EXPORT_DIRECTORY = "LastToolExportDirectory";

	/**
	 * Preference name for directory last selected for creating a new project.
	 */
	public final static String LAST_NEW_PROJECT_DIRECTORY = "LastNewProjectDirectory";

	/**
	 * Preference name for the import directory that was last accessed for
	 * domain files.
	 */
	public final static String LAST_IMPORT_DIRECTORY = "LastImportDirectory";
	/**
	 * Preference name for the export directory that was last accessed.
	 */
	public final static String LAST_EXPORT_DIRECTORY = "LastExportDirectory";

	/**
	 * The data storage for this class.
	 */
	private static Properties properties = new Properties();

	/**
	 * Data storage that contains preferences data from a previous installation.
	 */
	private static Properties previousProperties = new Properties();

	private static String filename = null;

	// Always attempt to load initial user preferences
	static {
		try {
			File userSettingsDir = Application.getUserSettingsDirectory();
			if (userSettingsDir != null) {
				load(userSettingsDir.getAbsolutePath() + File.separatorChar +
					APPLICATION_PREFERENCES_FILENAME);
			}
		}
		catch (Exception e) {
			Msg.error(Preferences.class, "Unexpected exception reading preferences file: ", e);
		}
	}

	/**
	 * Don't allow instantiation of this class.
	 */
	private Preferences() {
		// utils class
	}

	/**
	 * Initialize properties by reading name, values from the given filename.
	 * @param pathName name of preferences file to read in; could be null
	 * @throws IOException if there is a problem reading the file
	 */
	private static void load(String pathName) throws IOException {
		// create properties
		Msg.info(Preferences.class, "Loading user preferences: " + pathName);
		properties = new Properties();
		filename = pathName;

		File file = new File(pathName);
		if (file.exists()) {
			try (FileInputStream in = new FileInputStream(pathName)) {
				properties.load(in);
			}
		}

		// Try to load a previous installation's preferences so that they are usable as a 
		// reference point for those clients that wish to maintain previous values.  Note that 
		// not all previous values should be used in a new application, as that may 
		// cause issues when running; for example, path preferences can cause compile issues.
		loadPreviousInstallationPreferences();
	}

	private static void loadPreviousInstallationPreferences() throws IOException {
		try (FileInputStream fis = getAlternateFileInputStream()) {
			if (fis != null) {
				previousProperties.load(fis);
			}
		}
	}

	/**
	 * Clears all properties in this Preferences object.
	 * <p>
	 * <b>Warning: </b>Save any changes pending before calling this method, as this call will
	 * erase any changes not written do disk via {@link #store()}
	 */
	public static void clear() {
		properties.clear();
	}

	/**
	 * Gets an input stream to a file that is the same named file within a different 
	 * application version directory for this user. This method will search for an 
	 * alternate file based on the application version directories modification times 
	 * and will use the first matching file it finds.  
	 * 
	 * @return a file input stream for an alternate file or null.
	 */
	private static FileInputStream getAlternateFileInputStream() {
		File previousFile =
			GenericRunInfo.getPreviousApplicationSettingsFile(APPLICATION_PREFERENCES_FILENAME);
		if (previousFile == null) {
			return null;
		}

		try {
			FileInputStream fis = new FileInputStream(previousFile);
			Msg.info(Preferences.class, "Loading previous preferences: " + previousFile);
			return fis;
		}
		catch (FileNotFoundException fnfe) {
			// Ignore so we can try another directory.
		}

		return null;
	}

	/**
	 * Removes the given preference from this preferences object.
	 * 
	 * @param name the name of the preference key to remove.
	 * @return the value that was stored with the given key.
	 */
	public static String removeProperty(String name) {
		return (String) properties.remove(name);
	}

	/**
	 * Get the property with the given name.
	 * <p>
	 * Note: all <code>getProperty(...)</code> methods will first check {@link System#getProperty(String)}
	 * for a value first.  This allows users to override preferences from the command-line.
	 * @param name the property name
	 * @return the current property value; null if not set
	 */
	public static String getProperty(String name) {
		// prefer system properties, which enables uses to override preferences from the command-line
		String systemProperty = System.getProperty(name);
		if (systemProperty != null) {
			return systemProperty;
		}

		return properties.getProperty(name, null);
	}

	/**
	 * Get the property with the given name; if there is no property, return the defaultValue.
	 * <p>
	 * Note: all <code>getProperty(...)</code> methods will first check {@link System#getProperty(String)}
	 * for a value first.  This allows users to override preferences from the command-line.
	 * @param name the property name
	 * @param defaultValue the default value
	 * @return the property value; default value if not set
	 * 
	 * @see #getProperty(String, String, boolean)
	 */
	public static String getProperty(String name, String defaultValue) {
		// prefer system properties, which enables uses to override preferences from the command-line
		String systemProperty = System.getProperty(name);
		if (systemProperty != null) {
			return systemProperty;
		}

		return properties.getProperty(name, defaultValue);
	}

	/**
	 * Get the property with the given name; if there is no property, return the defaultValue.
	 * <p>
	 * This version of <code>getProperty</code> will, when <code>useHistoricalValue</code> is true, look
	 * for the given preference value in the last used installation of the application.
	 * <p>
	 * Note: all <code>getProperty(...)</code> methods will first check {@link System#getProperty(String)}
	 * for a value first.  This allows users to override preferences from the command-line.
	 * 
	 * @param name The name of the property for which to get a value
	 * @param defaultValue The value to use if there is no value yet set for the given name
	 * @param useHistoricalValue True signals to check the last used application installation for a 
	 *        value for the given name <b>if that value has not yet been set</b>.
	 * @return the property with the given name; if there is no property,
	 *         return the defaultValue.
	 * @see #getProperty(String)
	 * @see #getProperty(String, String)
	 */
	public static String getProperty(String name, String defaultValue, boolean useHistoricalValue) {
		// prefer system properties, which enables uses to override preferences from the command-line
		String systemProperty = System.getProperty(name);
		if (systemProperty != null) {
			return systemProperty;
		}

		String currentValue = properties.getProperty(name);
		if (currentValue != null) {
			return currentValue;
		}

		if (!useHistoricalValue) {
			return defaultValue;
		}

		return previousProperties.getProperty(name, defaultValue);
	}

	/**
	 * Set the property value.  If a null value is passed, then the property is removed from 
	 * this collection of preferences.
	 * 
	 * @param name property name
	 * @param value value for property
	 */
	public static void setProperty(String name, String value) {
		if (value == null) {
			Msg.trace(Preferences.class, "clearing property " + name);
			properties.remove(name);
			return;
		}
		Msg.trace(Preferences.class, "setting property " + name + "=" + value);
		properties.setProperty(name, value);
	}

	/**
	 * Get an array of known property names.
	 * @return if there are no properties, return a zero-length array
	 */
	public static List<String> getPropertyNames() {
		Collection<String> backedCollection =
			CollectionUtils.asCollection(properties.keySet(), String.class);
		return new LinkedList<>(backedCollection);
	}

	/**
	 * Get the filename that will be used in the store() method.
	 * @return the filename
	 */
	public static String getFilename() {
		return filename;
	}

	/**
	 * Set the filename so that when the store() method is called, the
	 * preferences are written to this file.
	 * @param name the filename
	 */
	public static void setFilename(String name) {
		filename = name;
	}

	/**
	 * Store the preferences in a file for the current filename.
	 * @return true if the file was written
	 * @throws RuntimeException if the preferences filename was not set
	 */
	public static boolean store() {
		if (filename == null) {
			throw new RuntimeException("Preferences filename has not been set!");
		}
		Msg.trace(Preferences.class, "Storing user preferences: " + filename);

		// make sure the preferences directory exists.
		File file = new File(filename);
		if (!file.exists()) {
			FileUtilities.mkdirs(file.getParentFile());
		}

		// Save properties to file
		BufferedOutputStream os = null;
		try {
			os = new BufferedOutputStream(new FileOutputStream(filename));
			properties.store(os, "User Preferences");
			os.close();
			return true;
		}
		catch (IOException e) {
			Msg.error(Preferences.class, "Failed to store user preferences: " + filename);
		}
		finally {
			if (os != null) {
				try {
					os.close();
				}
				catch (IOException e) {
					// we tried
				}
			}
		}
		return false;
	}

	/**
	 * Return the paths in the UserPluginPath property.
	 * Return zero length array if this property is not set.
	 * @return the paths
	 *
	 */
	public static String[] getPluginPaths() {
		List<String> list = getPluginPathList();
		if (list == null) {
			return new String[0];
		}

		return list.toArray(new String[list.size()]);
	}

	/**
	 * Set the paths to be used as the UserPluginPath property.
	 * @param paths the paths
	 */
	public static void setPluginPaths(String[] paths) {
		if (paths == null || paths.length == 0) {
			properties.remove(USER_PLUGIN_PATH);
			return;
		}

		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < paths.length; i++) {
			sb.append(paths[i]);
			if (i < paths.length - 1) {
				sb.append(File.pathSeparator);
			}
		}
		properties.setProperty(USER_PLUGIN_PATH, sb.toString());
	}

	private static List<String> getPluginPathList() {
		String path = properties.getProperty(USER_PLUGIN_PATH);
		if (path == null) {
			return null;
		}

		List<String> list = new ArrayList<>(5);

		StringTokenizer st = new StringTokenizer(path, File.pathSeparator);
		while (st.hasMoreElements()) {
			String p = (String) st.nextElement();
			list.add(p);
		}
		return list;
	}
}
