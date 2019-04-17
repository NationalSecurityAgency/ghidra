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
package ghidra.app.util.bin.format;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg;

import java.io.*;
import java.util.Properties;

public class ClampPropertiesLookup {
	public static final String CLAMP_PROPERTIES_FILENAME = "formats/clamp.properties";

	private static boolean UNINITIALIZED = true;
	private static Properties properties = null;

	public static long getClampValue(String clampKey, long defaultValue) {
		initialize();
		try {
			String property = properties.getProperty(clampKey);
			if (property != null) {
				try {
					long value = Long.parseLong(property);
					return value;
				}
				catch (NumberFormatException e) {
					return defaultValue;
				}
			}
		}
		catch (NullPointerException e) {
			// no such property
		}
		return defaultValue;
	}

	private static synchronized void initialize() {
		if (UNINITIALIZED) {
			InputStream inputStream = null;
			try {
				ResourceFile propertiesFile =
					Application.getModuleDataFile(CLAMP_PROPERTIES_FILENAME);
				properties = new Properties();
				inputStream = propertiesFile.getInputStream();
				properties.load(inputStream);

			}
			catch (FileNotFoundException e) {
				Msg.warn(ClampPropertiesLookup.class, "couldn't find clamp properties file");
			}
			catch (IOException e) {
				Msg.warn(ClampPropertiesLookup.class, "IOException reading clamp properties file",
					e);
			}
			finally {
				if (inputStream != null) {
					try {
						inputStream.close();
					}
					catch (IOException e) {
						// yeah well we tried
					}
				}
			}
			UNINITIALIZED = false;
		}
	}
}
