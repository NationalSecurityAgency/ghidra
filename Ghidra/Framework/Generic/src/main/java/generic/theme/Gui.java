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

import java.awt.Color;
import java.awt.Font;
import java.io.*;
import java.util.*;

import javax.swing.Icon;
import javax.swing.UIManager;
import javax.swing.plaf.ComponentUI;

import com.formdev.flatlaf.*;

import generic.theme.builtin.*;
import generic.theme.laf.LookAndFeelManager;
import ghidra.framework.*;
import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import resources.ResourceManager;
import utilities.util.reflection.ReflectionUtilities;

// TODO doc what this concept is
public class Gui {
	public static final String THEME_DIR = "themes";
	public static final String BACKGROUND_KEY = "color.bg.text";

	private static final String THEME_PREFFERENCE_KEY = "Theme";

	private static GTheme activeTheme = getDefaultTheme();
	private static Set<GTheme> allThemes = null;

	private static GThemeValueMap ghidraLightDefaults = new GThemeValueMap();
	private static GThemeValueMap ghidraDarkDefaults = new GThemeValueMap();
	private static GThemeValueMap javaDefaults = new GThemeValueMap();
	private static GThemeValueMap currentValues = new GThemeValueMap();

	private static ThemePropertiesLoader themePropertiesLoader = new ThemePropertiesLoader();

	private static Map<String, GColorUIResource> gColorMap = new HashMap<>();
	private static boolean isInitialized;
	private static Map<String, GIconUIResource> gIconMap = new HashMap<>();

	// these notifications are only when the user is manipulating theme values, so rare and at
	// user speed, so using copy on read
	private static WeakSet<ThemeListener> themeListeners =
		WeakDataStructureFactory.createCopyOnReadWeakSet();

	// stores the original value for ids whose value has changed from the current theme
	private static GThemeValueMap changedValuesMap = new GThemeValueMap();
	private static LookAndFeelManager lookAndFeelManager;

	private Gui() {
		// static utils class, can't construct
	}

	public static void initialize() {
		isInitialized = true;
		installFlatLookAndFeels();
		loadThemeDefaults();
		setTheme(getThemeFromPreferences());
//		LookAndFeelUtils.installGlobalOverrides();
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
		lookAndFeelManager.update();
		notifyThemeValuesRestored();
	}

	public static void restoreThemeValues() {
		buildCurrentValues();
		lookAndFeelManager.update();
		notifyThemeValuesRestored();
	}

	public static void setTheme(GTheme theme) {
		if (theme.hasSupportedLookAndFeel()) {
			activeTheme = theme;
			LafType lookAndFeel = theme.getLookAndFeelType();
			lookAndFeelManager = lookAndFeel.getLookAndFeelManager();
			try {
				lookAndFeelManager.installLookAndFeel();
				notifyThemeChanged();
				saveThemeToPreferences(theme);
			}
			catch (Exception e) {
				Msg.error(Gui.class, "Error setting LookAndFeel: " + lookAndFeel.getName(), e);
			}
		}
	}

	private static void notifyThemeChanged() {
		for (ThemeListener listener : themeListeners) {
			listener.themeChanged(activeTheme);
		}
	}

	private static void notifyThemeValuesRestored() {
		for (ThemeListener listener : themeListeners) {
			listener.themeValuesRestored();
		}
	}

	private static void notifyColorChanged(String id) {
		for (ThemeListener listener : themeListeners) {
			listener.colorChanged(id);
		}
	}

	private static void notifyFontChanged(String id) {
		for (ThemeListener listener : themeListeners) {
			listener.fontChanged(id);
		}
	}

	private static void notifyIconChanged(String id) {
		for (ThemeListener listener : themeListeners) {
			listener.iconChanged(id);
		}
	}

	public static void addTheme(GTheme newTheme) {
		loadThemes();
		allThemes.remove(newTheme);
		allThemes.add(newTheme);
	}

	public static void deleteTheme(FileGTheme theme) {
		theme.file.delete();
		if (allThemes != null) {
			allThemes.remove(theme);
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
		loadThemes();
		return new HashSet<>(allThemes);
	}

	public static Set<GTheme> getSupportedThemes() {
		loadThemes();
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

	public static Color getRawColor(String id) {
		return getRawColor(id, true);
	}

	static Color getRawColor(String id, boolean validate) {
		ColorValue color = currentValues.getColor(id);

		if (color == null) {
			if (validate && isInitialized) {
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
			if (validate && isInitialized) {
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
		changedValuesMap.clear();
	}

	private static void loadThemes() {
		if (allThemes == null) {
			Set<GTheme> set = new HashSet<>();
			set.addAll(findDiscoverableThemes());
			set.addAll(loadThemesFromFiles());
			allThemes = set;
		}
	}

	private static Collection<GTheme> loadThemesFromFiles() {
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
		return getDefaultTheme();
	}

	public static void setFont(FontValue newValue) {
		FontValue currentValue = currentValues.getFont(newValue.getId());
		if (newValue.equals(currentValue)) {
			return;
		}
		updateChangedValuesMap(currentValue, newValue);

		currentValues.addFont(newValue);
		// all fonts are direct (there is no GFont), so to we need to update the
		// UiDefaults for java fonts. Ghidra fonts are expected to be "on the fly" (they
		// call Gui.getFont(id) for every use. 
		String id = newValue.getId();
		boolean isJavaFont = javaDefaults.containsFont(id);
		lookAndFeelManager.updateFont(id, newValue.get(currentValues), isJavaFont);
		notifyFontChanged(id);
	}

	public static void setColor(String id, Color color) {
		setColor(new ColorValue(id, color));
	}

	public static void setColor(ColorValue newValue) {
		ColorValue currentValue = currentValues.getColor(newValue.getId());
		if (newValue.equals(currentValue)) {
			return;
		}
		updateChangedValuesMap(currentValue, newValue);

		currentValues.addColor(newValue);
		String id = newValue.getId();
		boolean isJavaColor = javaDefaults.containsColor(id);
		lookAndFeelManager.updateColor(id, newValue.get(currentValues), isJavaColor);
		notifyColorChanged(newValue.getId());
	}

	private static void updateChangedValuesMap(ColorValue currentValue, ColorValue newValue) {
		String id = newValue.getId();
		ColorValue originalValue = changedValuesMap.getColor(id);

		// if new value is original value, it is no longer changed, remove it from changed map
		if (newValue.equals(originalValue)) {
			changedValuesMap.removeColor(id);
		}
		else if (originalValue == null) {
			// first time changed, so current value is original value
			changedValuesMap.addColor(currentValue);
		}
	}

	private static void updateChangedValuesMap(FontValue currentValue, FontValue newValue) {
		String id = newValue.getId();
		FontValue originalValue = changedValuesMap.getFont(id);

		// if new value is original value, it is no longer changed, remove it from changed map
		if (newValue.equals(originalValue)) {
			changedValuesMap.removeFont(id);
		}
		else if (originalValue == null) {
			// first time changed, so current value is original value
			changedValuesMap.addFont(currentValue);
		}
	}

	private static void updateChangedValuesMap(IconValue currentValue, IconValue newValue) {
		String id = newValue.getId();
		IconValue originalValue = changedValuesMap.getIcon(id);

		// if new value is original value, it is no longer changed, remove it from changed map
		if (newValue.equals(originalValue)) {
			changedValuesMap.removeIcon(id);
		}
		else if (originalValue == null) {
			// first time changed, so current value is original value
			changedValuesMap.addIcon(currentValue);
		}
	}

	public static void setIcon(String id, Icon icon) {
		setIcon(new IconValue(id, icon));
	}

	public static void setIcon(IconValue newValue) {
		IconValue currentValue = currentValues.getIcon(newValue.getId());
		if (newValue.equals(currentValue)) {
			return;
		}
		updateChangedValuesMap(currentValue, newValue);

		currentValues.addIcon(newValue);
		String id = newValue.getId();
		boolean isJavaIcon = javaDefaults.containsIcon(id);
		lookAndFeelManager.updateIcon(id, newValue.get(currentValues), isJavaIcon);
		notifyIconChanged(id);
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
		javaDefaults = fixupJavaDefaultsInheritence(map);
		buildCurrentValues();
		GColor.refreshAll();
		GIcon.refreshAll();
	}

	public static GThemeValueMap fixupJavaDefaultsInheritence(GThemeValueMap map) {
		List<ColorValue> colors = javaDefaults.getColors();
		JavaColorMapping mapping = new JavaColorMapping();
		for (ColorValue value : colors) {
			ColorValue mapped = mapping.map(javaDefaults, value);
			if (mapped != null) {
				javaDefaults.addColor(mapped);
			}
		}
		return map;
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

	/**
	 * Returns true if the given UI object is using the Aqua Look and Feel.
	 * @param UI the UI to examine.
	 * @return true if the UI is using Aqua
	 */
	public static boolean isUsingAquaUI(ComponentUI UI) {
		return activeTheme.getLookAndFeelType() == LafType.MAC;
	}

	/**
	 * Returns true if 'Nimbus' is the current Look and Feel
	 * @return true if 'Nimbus' is the current Look and Feel
	 */
	public static boolean isUsingNimbusUI() {
		return activeTheme.getLookAndFeelType() == LafType.NIMBUS;
	}

	public static void addThemeListener(ThemeListener listener) {
		themeListeners.add(listener);
	}

	public static void removeThemeListener(ThemeListener listener) {
		themeListeners.add(listener);
	}

	// for testing
	public static void setPropertiesLoader(ThemePropertiesLoader loader) {
		themePropertiesLoader = loader;
	}

	public static GTheme getDefaultTheme() {
		OperatingSystem OS = Platform.CURRENT_PLATFORM.getOperatingSystem();
		switch (OS) {
			case MAC_OS_X:
				return new MacTheme();
			case WINDOWS:
				return new WindowsTheme();
			case LINUX:
			case UNSUPPORTED:
			default:
				return new NimbusTheme();
		}
	}

	public static boolean hasThemeChanges() {
		return !changedValuesMap.isEmpty();
	}

}
