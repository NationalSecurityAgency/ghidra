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
	public static final String THEME_DIR = "themes";
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
	private static Map<String, GIconUIResource> gIconMap = new HashMap<>();
	private static boolean isInitialzed;

	static void setPropertiesLoader(ThemePropertiesLoader loader) {
		themePropertiesLoader = loader;
	}

	private Gui() {
		// static utils class, can't construct
	}

	public static void initialize() {
		isInitialzed = true;
		installFlatLookAndFeels();
		loadThemeDefaults();
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

	private static void loadThemeDefaults() {
		themePropertiesLoader.load();
		ghidraLightDefaults = themePropertiesLoader.getDefaults();
		ghidraDarkDefaults = themePropertiesLoader.getDarkDefaults();
	}

	public static void reloadGhidraDefaults() {
		loadThemeDefaults();
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

	public static GThemeValueMap getNonDefaultValues() {
		return currentValues.getChangedValues(getDefaults());
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
		return first.orElse(null);
	}

	public static Color darker(Color color) {
		if (activeTheme.useDarkDefaults()) {
			return color.brighter();
		}
		return color.darker();
	}

	public static Color brighter(Color color) {
		if (activeTheme.useDarkDefaults()) {
			return color.darker();
		}
		return color.brighter();
	}

	public static Font getFont(String id) {
		FontValue font = currentValues.getFont(id);
		if (font == null) {
			Throwable t = getFilteredTrace();

			Msg.error(Gui.class, "No font value registered for: " + id, t);
			return null;
		}
		return font.get(currentValues);
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
			if (validate && isInitialzed) {
				//	Throwable t = getFilteredTrace();
				Msg.error(Gui.class, "No color value registered for: " + id);
			}
			return Color.CYAN;
		}
		return color.get(currentValues);
	}

	public static Icon getRawIcon(String id, boolean validate) {
		IconValue icon = currentValues.getIcon(id);
		if (icon == null) {
			if (validate && isInitialzed) {
				Throwable t = getFilteredTrace();
				Msg.error(Gui.class, "No icon value registered for: " + id, t);
			}
			return ResourceManager.getDefaultIcon();
		}
		return icon.get(currentValues);
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
		if (activeTheme.useDarkDefaults()) {
			map.load(ghidraDarkDefaults);
		}
		map.load(activeTheme);
		currentValues = map;
		GColor.refreshAll();
		GIcon.refreshAll();
		repaintAll();
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
		FileFilter themeFileFilter = file -> file.getName().endsWith(GTheme.FILE_EXTENSION);

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

	public static void setFont(FontValue newValue) {
		currentValues.addFont(newValue);
		// all fonts are direct (there is no GFont), so to we need to update the
		// UiDefaults for java fonts. Ghidra fonts are expected to be "on the fly" (they
		// call Gui.getFont(id) for every use. 
		String id = newValue.getId();
		if (javaDefaults.containsFont(id)) {
			UIManager.getDefaults().put(id, newValue.get(currentValues));
			updateUIs();
		}
		else {
			repaintAll();
		}
	}

	public static void setColor(String id, Color color) {
		setColor(new ColorValue(id, color));
	}

	public static void setColor(ColorValue colorValue) {
		currentValues.addColor(colorValue);
		// all colors use indirection via GColor, so to update all we need to do is refresh GColors
		// and repaint
		GColor.refreshAll();
		repaintAll();
	}

	public static void setIcon(String id, Icon icon) {
		setIcon(new IconValue(id, icon));
	}

	public static void setIcon(IconValue newValue) {
		currentValues.addIcon(newValue);

		// Icons are a mixed bag. Java Icons are direct and Ghidra Icons are indirect (to support static use)
		// Mainly because Nimbus is buggy and can't handle non-nimbus Icons, so we can't wrap them
		// So need to update UiDefaults for java icons. For Ghidra Icons, it is sufficient to refrech
		// GIcons and repaint
		String id = newValue.getId();
		if (javaDefaults.containsIcon(id)) {
			UIManager.getDefaults().put(id, newValue.get(currentValues));
			updateUIs();
		}
		else {
			GIcon.refreshAll();
			repaintAll();
		}
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

	public static GIconUIResource getGIconUiResource(String id) {

		GIconUIResource gIcon = gIconMap.get(id);
		if (gIcon == null) {
			gIcon = new GIconUIResource(id);
			gIconMap.put(id, gIcon);
		}
		return gIcon;
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
		if (activeTheme.useDarkDefaults()) {
			currentDefaults.load(ghidraDarkDefaults);
		}
		return currentDefaults;
	}

}
