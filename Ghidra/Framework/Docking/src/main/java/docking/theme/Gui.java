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
import javax.swing.plaf.UIResource;

import com.formdev.flatlaf.*;

import docking.framework.ApplicationInformationDisplayFactory;
import docking.help.Help;
import docking.theme.builtin.JavaColorMapping;
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

	private static GThemeValueMap ghidraLightDefaults = new GThemeValueMap();
	private static GThemeValueMap ghidraDarkDefaults = new GThemeValueMap();
	private static GThemeValueMap javaDefaults = new GThemeValueMap();
	private static GThemeValueMap currentValues = new GThemeValueMap();

	private static ThemePropertiesLoader themePropertiesLoader = new ThemePropertiesLoader();

	private static Map<String, GColorUIResource> gColorMap = new HashMap<>();

	private static JPanel jPanel;

	static void setPropertiesLoader(ThemePropertiesLoader loader) {
		themePropertiesLoader = loader;
	}

	private Gui() {
		// static utils class, can't construct
	}

	public static void initialize() {
		installFlatLookAndFeels();
		loadGhidraDefaults();
		setTheme(getThemeFromPreferences());
//		LookAndFeelUtils.installGlobalOverrides();
		platformSpecificFixups();
	}

	private static void installFlatLookAndFeels() {
		UIManager.installLookAndFeel(LafType.FLAT_LIGHT.getName(), FlatLightLaf.class.getName());
		UIManager.installLookAndFeel(LafType.FLAT_DARK.getName(), FlatDarkLaf.class.getName());
		UIManager.installLookAndFeel(LafType.FLAT_DARCULA.getName(),
			FlatDarculaLaf.class.getName());
	}

	private static void loadGhidraDefaults() {
		themePropertiesLoader.load();
		ghidraLightDefaults = themePropertiesLoader.getDefaults();
		ghidraDarkDefaults = themePropertiesLoader.getDarkDefaults();
	}

	public static void reloadGhidraDefaults() {
		loadGhidraDefaults();
		buildCurrentValues();
	}

	public static void restoreThemeValues() {
		buildCurrentValues();
	}

	public static void setTheme(GTheme theme) {
		if (theme.hasSupportedLookAndFeel()) {
			activeTheme = theme;
			LafType lookAndFeel = theme.getLookAndFeelType();
			try {
				lookAndFeel.install();
				saveThemeToPreferences(theme);
				fixupJavaDefaults();
				// The help may produce errors when switching the theme, such as if there is an 
				// active search in the help.  We have added this call to allow the help system
				// to cleanup some internal state.
				Help.getHelpService().reload();
				buildCurrentValues();
				updateUIs();
			}
			catch (Exception e) {
				Msg.error(Gui.class, "Error setting LookAndFeel: " + lookAndFeel.getName(), e);
			}
		}
	}

	public static void addTheme(GTheme newTheme) {
		allThemes.remove(newTheme);
		allThemes.add(newTheme);
	}

	private static void updateUIs() {
		for (Window window : Window.getWindows()) {
			SwingUtilities.updateComponentTreeUI(window);
		}
	}

	public static boolean isJavaDefinedColor(String id) {
		return javaDefaults.containsColor(id);
	}

	public static GThemeValueMap getAllValues() {
		return new GThemeValueMap(currentValues);
	}

	public static Set<GTheme> getAllThemes() {
		if (allThemes == null) {
			allThemes = findThemes();
		}
		return Collections.unmodifiableSet(allThemes);
	}

	public static Set<GTheme> getSupportedThemes() {
		if (allThemes == null) {
			allThemes = findThemes();
		}
		Set<GTheme> supported = new HashSet<>();
		for (GTheme theme : allThemes) {
			if (theme.hasSupportedLookAndFeel()) {
				supported.add(theme);
			}
		}
		return supported;
	}

	public static GTheme getTheme(String themeName) {
		Optional<GTheme> first =
			getAllThemes().stream().filter(t -> t.getName().equals(themeName)).findFirst();
		return first.get();
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

	public static void saveThemeToPreferences(GTheme theme) {
		Preferences.setProperty(THEME_PREFFERENCE_KEY, theme.getThemeLocater());
		Preferences.store();
	}

	public static GTheme getActiveTheme() {
		return activeTheme;
	}

	public static LafType getLookAndFeelType() {
		return activeTheme.getLookAndFeelType();
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

	public static Color getRawColor(String id) {
		return getRawColor(id, true);
	}

	static Color getRawColor(String id, boolean validate) {
		ColorValue color = currentValues.getColor(id);

		if (color == null) {
			if (validate) {
				//	Throwable t = getFilteredTrace();
				Msg.error(Gui.class, "No color value registered for: " + id);
			}
			return Color.CYAN;
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

	private static void buildCurrentValues() {
		GThemeValueMap map = new GThemeValueMap();

		map.load(javaDefaults);
		map.load(ghidraLightDefaults);
		if (activeTheme.isDark()) {
			map.load(ghidraDarkDefaults);
		}
		map.load(activeTheme);
		currentValues = map;
		GColor.refreshAll();
		repaintAll();
	}

	private static Color getUIColor(String id) {
		// Not sure, but for now, make sure colors are not UIResource
		Color color = UIManager.getColor(id);
		if (color instanceof UIResource) {
			return new Color(color.getRGB(), true);
		}
		return color;
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
		FileFilter themeFileFilter = file -> file.getName().endsWith(GTheme.FILE_EXTENSION);
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

	public static void setColor(String id, Color color) {
		setColor(new ColorValue(id, color));
	}

	public static void setColor(ColorValue colorValue) {
		currentValues.addColor(colorValue);
		GColor.refreshAll();
		repaintAll();
	}

	private static void repaintAll() {
		for (Window window : Window.getWindows()) {
			window.repaint();
		}
	}

	public static GColorUIResource getGColorUiResource(String id) {
		GColorUIResource gColor = gColorMap.get(id);
		if (gColor == null) {
			gColor = new GColorUIResource(id);
			gColorMap.put(id, gColor);
		}
		return gColor;
	}

	public static void setJavaDefaults(GThemeValueMap map) {
		javaDefaults = map;
		buildCurrentValues();
	}

	public static void fixupJavaDefaults() {
		List<ColorValue> colors = javaDefaults.getColors();
		JavaColorMapping mapping = new JavaColorMapping();
		for (ColorValue value : colors) {
			ColorValue mapped = mapping.map(javaDefaults, value);
			if (mapped != null) {
				javaDefaults.addColor(mapped);
			}
		}
	}

	public static GThemeValueMap getJavaDefaults() {
		GThemeValueMap map = new GThemeValueMap();
		map.load(javaDefaults);
		return map;
	}

	public static GThemeValueMap getGhidraDarkDefaults() {
		GThemeValueMap map = new GThemeValueMap(ghidraLightDefaults);
		map.load(ghidraDarkDefaults);
		return map;
	}

	public static GThemeValueMap getGhidraLightDefaults() {
		GThemeValueMap map = new GThemeValueMap(ghidraLightDefaults);
		return map;
	}

	public static GThemeValueMap getDefaults() {
		GThemeValueMap currentDefaults = new GThemeValueMap(javaDefaults);
		currentDefaults.load(ghidraLightDefaults);
		if (activeTheme.isDark()) {
			currentDefaults.load(ghidraDarkDefaults);
		}
		return currentDefaults;
	}
}
