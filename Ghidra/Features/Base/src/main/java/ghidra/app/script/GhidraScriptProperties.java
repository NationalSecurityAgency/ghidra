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
package ghidra.app.script;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.util.Msg;

/**
 * Handles processing for .properties files associated with a GhidraScript (.properties file and
 * script should share the same basename).
 * 
 * <p>This should only be called/used by the GhidraScript class. 
 */
public class GhidraScriptProperties {

	private HashMap<String, String> propertiesMap;
	private String baseName;

	GhidraScriptProperties() {
		propertiesMap = new HashMap<>();
	}

	/** 
	 * Load a .properties file given a directory (ResourceFile) and the basename (i.e., name of the
	 * GhidraScript without the extension).
	 * 
	 * @param scriptLocation  location of the GhidraScript
	 * @param newBaseName  name of the GhidraScript (without the extension)
	 * @throws IOException if there is an exception loading the properties file
	 */
	protected void loadGhidraScriptProperties(ResourceFile scriptLocation, String newBaseName)
			throws IOException {

		this.baseName = newBaseName;
		if (scriptLocation.isDirectory()) {
			// File we're looking for (strip off extension and append .properties)
			String propFileName = newBaseName + ".properties";

			ResourceFile[] childFiles = scriptLocation.listFiles();
			ResourceFile propFile = null;

			for (ResourceFile chFile : childFiles) {
				if (chFile.getName().equals(propFileName)) {
					propFile = chFile;
					break;
				}
			}

			if (propFile != null) {
				loadGhidraScriptProperties(propFile);
			}
		}
		else {
			Msg.warn(this,
				"The path '" + scriptLocation.toString() + "' is not a valid directory.");
		}
	}

	/**
	 * @return the properties file name
	 */
	public String getFilename() {
		return baseName + ".properties";
	}

	/**
	 * Look for a .properties file corresponding to the basename in the given locations.
	 * 
	 * @param possibleLocations possible locations where the .properties file can be found
	 * @param newBaseName name of the GhidraScript (without the extension)
	 * @throws IOException if there is an exception loading the properties file
	 */
	protected void loadGhidraScriptProperties(List<ResourceFile> possibleLocations,
			String newBaseName) throws IOException {

		for (ResourceFile location : possibleLocations) {
			loadGhidraScriptProperties(location, newBaseName);

			if (!isEmpty()) {
				break;
			}
		}
	}

	/**
	 * Load a .properties file.
	 * 
	 * @param file  the .properties file
	 * @throws IOException if there is an exception loading the properties file
	 */
	protected void loadGhidraScriptProperties(ResourceFile file) throws IOException {

		Msg.info(this, "Reading script properties file: " + file.getAbsolutePath());
		if (!file.isFile()) {
			Msg.warn(this, ".properties file '" + file.toString() + "' is not a valid file.");
			return;
		}

		try (Scanner scanner = new Scanner(file.getInputStream(), "ASCII")) {

			while (scanner.hasNextLine()) {
				String line = scanner.nextLine().trim();

				// Ignore any comments or empty lines
				if (line.startsWith("#") || line.startsWith("!") || line.isEmpty()) {
					continue;
				}

				// break on '=' character
				int equalsIndex = line.indexOf('=');
				if (equalsIndex > 0) {
					String key = line.substring(0, equalsIndex).trim();
					String value = line.substring(equalsIndex + 1).trim();
					propertiesMap.put(key, value);
				}
			}
		}
		catch (FileNotFoundException fnfe) {
			throw new IOException("Could not find .properties file '" + file.toString() + "'");
		}
	}

	protected String put(String key, String value) {
		return propertiesMap.put(key.trim(), value);
	}

	/**
	 * @param keyString the property name
	 * @return the value of the key in the properties file, or an empty string if no property exists
	 */
	public String getValue(String keyString) {

		if (propertiesMap.size() == 0) {
			return "";
		}

		if (propertiesMap.containsKey(keyString)) {
			return propertiesMap.get(keyString);
		}

		return "";
	}

	/**
	 * @return true if there are no properties
	 */
	public boolean isEmpty() {
		return (propertiesMap.size() == 0);
	}

	/**
	 * Remove the named property
	 * 
	 * @param keyString the property name
	 * @return the previous value or null
	 */
	protected String remove(String keyString) {
		return propertiesMap.remove(keyString);
	}

	protected void clearProperties() {
		propertiesMap.clear();
	}

	/**
	 * @param keyString a property name
	 * @return true if the key exists in the property file
	 */
	public boolean containsKey(String keyString) {
		return propertiesMap.containsKey(keyString);
	}

	/**
	 * @param valueString a value string
	 * @return true if any property has the given value
	 */
	public boolean containsValue(String valueString) {
		return propertiesMap.containsValue(valueString);
	}

	/**
	 * @return the property names for all properties
	 */
	public Set<String> keySet() {
		return propertiesMap.keySet();
	}

	protected Collection<String> values() {
		return propertiesMap.values();
	}
}
