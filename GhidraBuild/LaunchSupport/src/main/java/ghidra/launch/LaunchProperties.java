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
package ghidra.launch;

import java.io.*;
import java.text.ParseException;
import java.util.*;

import ghidra.launch.JavaFinder.Platform;

/**
 * Parses and provides convenient access to the properties defined in a launch properties file.
 * <p>
 * Our launch properties file is a bit different than a file represented by a {@link Properties} 
 * object because we allow for duplicate keys.  The Apache commons config library can do this, but 
 * this project cannot have any external dependencies.
 */
public class LaunchProperties {

	/**
	 * The home directory of the Java to use to launch.
	 */
	public static String JAVA_HOME_OVERRIDE = "JAVA_HOME_OVERRIDE";

	/**
	 * The VM arguments to use to launch (all platforms).
	 */
	public static String VMARGS = "VMARGS";

	/**
	 * The VM arguments to use to launch (current platform only).
	 */
	public static String VMARGS_PLATFORM = "VMARGS_" + JavaFinder.getCurrentPlatform();

	private Map<String, List<String>> propertyMap;

	/**
	 * Creates a new launch properties object from the given launch properties file.
	 * 
	 * @param launchPropertiesFile The launch properties file.
	 * @throws FileNotFoundException if the given launch properties file does not exist.
	 * @throws IOException if there was a problem reading the given launch properties file.
	 * @throws ParseException if there was a problem parsing the given launch properties file.
	 */
	public LaunchProperties(File launchPropertiesFile)
			throws FileNotFoundException, IOException, ParseException {
		propertyMap = parseLaunchProperties(launchPropertiesFile);
	}

	/**
	 * Gets the Java home override directory to use for the launch.
	 * 
	 * @return The Java home override directory to use for the launch.  Could be null if the 
	 *   property was not defined.  The caller should ensure that the directory exists.
	 */
	public File getJavaHomeOverride() {
		List<String> javaHome = propertyMap.get(JAVA_HOME_OVERRIDE);
		if (javaHome != null && !javaHome.isEmpty()) {
			return new File(javaHome.get(0));
		}
		return null;
	}

	/**
	 * Gets the command line string of VM arguments to use for the launch for the current 
	 * {@link Platform platform}.
	 * 
	 * @return The command line string of VM arguments to use for the launch for the current
	 *   {@link Platform}
	 */
	public String getVmArgs() {
		StringBuilder sb = new StringBuilder();
		List<String> vmargList = propertyMap.get(VMARGS);
		if (vmargList != null) {
			for (String arg : vmargList) {
				sb.append(arg);
				sb.append(" ");
			}
		}
		List<String> vmargPlatformList = propertyMap.get(VMARGS_PLATFORM);
		if (vmargPlatformList != null) {
			for (String arg : vmargPlatformList) {
				sb.append(arg);
				sb.append(" ");
			}
		}
		return sb.toString();
	}

	/**
	 * Parses and gets the launch properties from the given launch properties file.
	 * 
	 * @param launchPropertiesFile The file to get the launch properties from.
	 * @return The launch properties from the given launch properties file.
	 * @throws FileNotFoundException if the given launch properties file does not exist.
	 * @throws IOException if there was a problem reading the given launch properties file.
	 * @throws ParseException if there was a problem parsing the given launch properties file.
	 */
	private static Map<String, List<String>> parseLaunchProperties(File launchPropertiesFile)
			throws FileNotFoundException, IOException, ParseException {
		HashMap<String, List<String>> map = new HashMap<>();
		if (launchPropertiesFile != null) {
			try (BufferedReader reader = new BufferedReader(new FileReader(launchPropertiesFile))) {
				int i = 0;
				String line;
				while ((line = reader.readLine()) != null) {
					i++;
					line = line.trim();
					if (line.isEmpty() || line.startsWith("#") || line.startsWith("//")) {
						continue;
					}
					int equalsIndex = line.indexOf('=');
					if (equalsIndex <= 0) {
						throw new ParseException(
							"Error parsing line " + i + " of " + launchPropertiesFile, i);
					}
					String key = line.substring(0, equalsIndex).trim();
					String value = line.substring(equalsIndex + 1, line.length()).trim();
					List<String> valueList = map.get(key);
					if (valueList == null) {
						valueList = new ArrayList<>();
						map.put(key, valueList);
					}
					if (!value.isEmpty()) {
						valueList.add(value);
					}
				}
			}
		}
		return map;
	}
}
