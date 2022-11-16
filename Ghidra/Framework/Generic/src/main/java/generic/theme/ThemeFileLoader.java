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
package generic.theme;

import java.io.*;
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg;

/**
 * Loads all the system theme.property files that contain all the default color, font, and
 * icon values.
 */
public class ThemeFileLoader {
	public static final String THEME_DIR = "themes";

	private GThemeValueMap defaults = new GThemeValueMap();
	private GThemeValueMap darkDefaults = new GThemeValueMap();

	/**
	 * Searches for all the theme.property files and loads them into either the standard
	 * defaults (light) map or the dark defaults map.
	 */
	public void loadThemeDefaultFiles() {
		defaults.clear();
		darkDefaults.clear();

		List<ResourceFile> themeDefaultFiles =
			Application.findFilesByExtensionInApplication(".theme.properties");

		for (ResourceFile resourceFile : themeDefaultFiles) {
			try {
				ThemePropertyFileReader reader = new ThemePropertyFileReader(resourceFile);
				defaults.load(reader.getDefaultValues());
				darkDefaults.load(reader.getDarkDefaultValues());
			}
			catch (IOException e) {
				Msg.error(this,
					"Error reading theme properties file: " + resourceFile.getAbsolutePath(), e);
			}
		}
	}

	public Collection<GTheme> loadThemeFiles() {
		List<File> fileList = new ArrayList<>();
		FileFilter themeFileFilter = file -> file.getName().endsWith("." + GTheme.FILE_EXTENSION);

		File dir = Application.getUserSettingsDirectory();
		File themeDir = new File(dir, THEME_DIR);
		File[] files = themeDir.listFiles(themeFileFilter);
		if (files != null) {
			fileList.addAll(Arrays.asList(files));
		}

		List<GTheme> list = new ArrayList<>();
		for (File file : fileList) {
			GTheme theme = loadTheme(file);
			if (theme != null) {
				list.add(theme);
			}
		}
		return list;

	}

	/**
	 * Returns the standard defaults {@link GThemeValueMap}
	 * @return the standard defaults {@link GThemeValueMap}
	 */
	public GThemeValueMap getDefaults() {
		return defaults;
	}

	/**
	 * Returns the dark defaults {@link GThemeValueMap}
	 * @return the dark defaults {@link GThemeValueMap}
	 */
	public GThemeValueMap getDarkDefaults() {
		return darkDefaults;
	}

	private static GTheme loadTheme(File file) {
		try {
			return new ThemeReader(file).readTheme();
		}
		catch (IOException e) {
			Msg.error(Gui.class, "Could not load theme from file: " + file.getAbsolutePath(), e);
		}
		return null;
	}
}
