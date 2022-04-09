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

import java.awt.*;
import java.io.*;
import java.util.*;
import java.util.List;

import javax.swing.*;

import docking.framework.ApplicationInformationDisplayFactory;
import ghidra.docking.util.LookAndFeelUtils;
import ghidra.framework.Application;
import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import resources.ResourceManager;
import utilities.util.reflection.ReflectionUtilities;

// TODO doc what this concept is
public class Gui {

	public static final String BACKGROUND_KEY = "color.bg.text";

	private static final String THEME_PREFFERENCE_KEY = "Theme";

	private static GTheme activeTheme = new DefaultTheme();
	private static Set<GTheme> allThemes;

	private static GThemeValueMap ghidraCoreDefaults = new GThemeValueMap();
	private static GThemeValueMap javaDefaults;
	private static GThemeValueMap currentValues = new GThemeValueMap();

	private static GThemeValueMap darkDefaults = new GThemeValueMap();

	private static ThemePropertiesLoader themePropertiesLoader = new ThemePropertiesLoader();

	static void setPropertiesLoader(ThemePropertiesLoader loader) {
		themePropertiesLoader = loader;
	}

	private Gui() {
		// static utils class, can't construct
	}

	public static void initialize() {
		themePropertiesLoader.initialize();
		loadThemeDefaults();
		setTheme(getThemeFromPreferences());
		LookAndFeelUtils.installGlobalOverrides();
		platformSpecificFixups();
	}

	private static void loadThemeDefaults() {
		ghidraCoreDefaults = themePropertiesLoader.getDefaults();
		darkDefaults = themePropertiesLoader.getDarkDefaults();
	}

	public static void setTheme(GTheme theme) {
		activeTheme = theme;
		LookAndFeelUtils.setLookAndFeel(theme.getLookAndFeelName());
		javaDefaults = mineJavaDefaults();
		currentValues = buildCurrentValues(theme);
		installBackIntoJava();
	}

	private static void installBackIntoJava() {
		UIDefaults defaults = UIManager.getDefaults();
		for (ColorValue color : javaDefaults.getColors()) {
			String id = color.getId();
			defaults.put(id, new GColor(id));
		}
	}

	public static boolean isJavaDefinedColor(String id) {
		return javaDefaults.containsColor(id);
	}

	public static GThemeValueMap getAllValues() {
		return new GThemeValueMap(currentValues);
	}

	public static GThemeValueMap getAllDefaultValues() {
		GThemeValueMap currentDefaults = new GThemeValueMap();
		currentDefaults.load(javaDefaults);
		currentDefaults.load(ghidraCoreDefaults);
		if (activeTheme.isDark()) {
			currentDefaults.load(darkDefaults);
		}
		return currentDefaults;
	}

	public static Set<GTheme> getAllThemes() {
		if (allThemes == null) {
			allThemes = findThemes();
		}
		return Collections.unmodifiableSet(allThemes);
	}

	public static Color darker(Color color) {
		if (activeTheme.isDark()) {
			return color.brighter();
		}
		return color.darker();
	}

	public static Color brighter(Color color) {
		if (activeTheme.isDark()) {
			return color.darker();
		}
		return color.brighter();
	}

	public static GFont getFont(String id) {
		return new GFont(id);
	}

	public static GIcon getIcon(String id) {
		return new GIcon(id);
	}

	public static void saveThemeToPreferneces(GTheme theme) {
		Preferences.setProperty(THEME_PREFFERENCE_KEY, theme.getThemeLocater());
		Preferences.store();
	}

	public static GTheme getActiveTheme() {
		return activeTheme;
	}

	public static String getLookAndFeelName() {
		return activeTheme.getLookAndFeelName();
	}

	private static void platformSpecificFixups() {

		// Set the dock icon for macOS
		if (Taskbar.isTaskbarSupported()) {
			Taskbar taskbar = Taskbar.getTaskbar();
			if (taskbar.isSupported(Taskbar.Feature.ICON_IMAGE)) {
				taskbar.setIconImage(ApplicationInformationDisplayFactory.getLargestWindowIcon());
			}
		}
	}

	static Color getRawColor(String id) {
		ColorValue color = currentValues.getColor(id);
		if (color == null) {
			Throwable t = getFilteredTrace();

			Msg.error(Gui.class, "No color value registered for: " + id, t);
			return null;
		}
		return color.get(currentValues);
	}

	static Font getRawFont(String id) {
		FontValue font = currentValues.getFont(id);
		if (font == null) {
			Throwable t = getFilteredTrace();

			Msg.error(Gui.class, "No font value registered for: " + id, t);
			return null;
		}
		return font.get(currentValues);
	}

	public static Icon getRawIcon(String id) {
		IconValue icon = currentValues.getIcon(id);
		if (icon == null) {
			Throwable t = getFilteredTrace();

			Msg.error(Gui.class, "No color value registered for: " + id, t);
			return null;
		}
		String iconPath = icon.get(currentValues);
		return ResourceManager.loadImage(iconPath);
	}

	private static Throwable getFilteredTrace() {
		Throwable t = ReflectionUtilities.createThrowableWithStackOlderThan();
		StackTraceElement[] trace = t.getStackTrace();
		StackTraceElement[] filtered =
			ReflectionUtilities.filterStackTrace(trace, "java.", "theme.Gui", "theme.GColor");
		t.setStackTrace(filtered);
		return t;
	}

	private static GThemeValueMap buildCurrentValues(GTheme theme) {
		GThemeValueMap map = new GThemeValueMap();

		map.load(javaDefaults);
		map.load(ghidraCoreDefaults);
		if (theme.isDark()) {
			map.load(darkDefaults);
		}
		map.load(theme);
		return map;
	}

	private static GThemeValueMap mineJavaDefaults() {
		GThemeValueMap values = new GThemeValueMap();
		// for now, just doing color properties.
		List<String> ids = LookAndFeelUtils.getLookAndFeelIdsForType(Color.class);
		for (String id : ids) {
			// Create a new color to ensure we are not storing a UIResource; otherwise java
			// java ignore the color because the UI widgets take liberties when UIResources
			// are being used.
			Color lafColor = new Color(UIManager.getColor(id).getRGB(), true);
			values.addColor(new ColorValue(id, lafColor));
		}
		return values;
	}

	private static Set<GTheme> findThemes() {
		Set<GTheme> set = new HashSet<>();
		set.addAll(findDiscoverableThemes());
		set.addAll(loadThemesFromFiles());

		// The set should contains a duplicate of the active theme. Make sure the active theme
		// instance is the one in the set
		set.remove(activeTheme);
		set.add(activeTheme);
		return set;
	}

	private static Collection<GTheme> loadThemesFromFiles() {
		List<File> fileList = new ArrayList<>();

		File dir = Application.getUserSettingsDirectory();
		FileFilter themeFileFilter = file -> file.getName().endsWith(".theme");
		fileList.addAll(Arrays.asList(dir.listFiles(themeFileFilter)));

		List<GTheme> list = new ArrayList<>();
		for (File file : fileList) {
			GTheme theme = loadTheme(file);
			if (theme != null) {
				list.add(theme);
			}
		}
		return list;
	}

	private static GTheme loadTheme(File file) {
		try {
			return new FileGTheme(file);
		}
		catch (IOException e) {
			Msg.error(Gui.class, "Could not load theme from file: " + file.getAbsolutePath());
		}
		return null;
	}

	private static Collection<DiscoverableGTheme> findDiscoverableThemes() {
		return ClassSearcher.getInstances(DiscoverableGTheme.class);
	}

	private static GTheme getThemeFromPreferences() {
		String themeId = Preferences.getProperty(THEME_PREFFERENCE_KEY, "Default", true);
		if (themeId.startsWith(FileGTheme.FILE_PREFIX)) {
			String filename = themeId.substring(FileGTheme.FILE_PREFIX.length());
			try {
				return new FileGTheme(new File(filename));
			}
			catch (IOException e) {
				Msg.showError(GTheme.class, null, "Can't Load Previous Theme",
					"Error loading theme file: " + filename);
			}
		}
		else if (themeId.startsWith(DiscoverableGTheme.CLASS_PREFIX)) {
			String className = themeId.substring(DiscoverableGTheme.CLASS_PREFIX.length());
			try {
				Class<?> forName = Class.forName(className);
				return (GTheme) forName.getDeclaredConstructor().newInstance();
			}
			catch (Exception e) {
				Msg.showError(GTheme.class, null, "Can't Load Previous Theme",
					"Can't find or instantiate class: " + className);
			}
		}
		return new DefaultTheme();
	}

	public static GThemeValueMap getCoreDefaults() {
		GThemeValueMap map = new GThemeValueMap(ghidraCoreDefaults);
		map.load(javaDefaults);
		return map;
	}

	public static GThemeValueMap getDarkDefaults() {
		GThemeValueMap map = new GThemeValueMap(ghidraCoreDefaults);
		map.load(darkDefaults);
		return map;
	}

}
