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
package docking.theme;

import java.io.IOException;
import java.util.List;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg;

public class ThemePropertiesLoader {
	GThemeValueMap defaults = new GThemeValueMap();
	GThemeValueMap darkDefaults = new GThemeValueMap();

	ThemePropertiesLoader() {
	}

	public void initialize() {
		List<ResourceFile> themeDefaultFiles =
			Application.findFilesByExtensionInApplication(".theme.properties");

		for (ResourceFile resourceFile : themeDefaultFiles) {
			Msg.debug(this, "found theme file: " + resourceFile.getAbsolutePath());
			try {
				ThemePropertyFileReader reader = new ThemePropertyFileReader(resourceFile);
				defaults.load(reader.getDefaultValues());
				darkDefaults.load(reader.getDarkDefaultValues());
			}
			catch (IOException e) {
				Msg.error(this,
					"Error reading theme properties file: " + resourceFile.getAbsolutePath());
			}
		}
	}

	public GThemeValueMap getDefaults() {
		return defaults;
	}

	public GThemeValueMap getDarkDefaults() {
		return darkDefaults;
	}

}
