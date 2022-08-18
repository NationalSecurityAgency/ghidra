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

import javax.swing.*;
import javax.swing.plaf.ComponentUI;
import javax.swing.plaf.basic.BasicLookAndFeel;

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

/**
 * Provides a static set of methods for globally managing application themes and their values.
 * <P>
 * The basic idea is that all the colors, fonts, and icons used in an application should be
 * accessed indirectly via an "id" string. Then the actual color, font, or icon can be changed 
 * without changing the source code. The default mapping of the id strings to a value is defined
 * in <name>.theme.properties files which are dynamically discovered by searching the module's
 * data directory. Also, these files can optionally define a dark default value for an id which
 * would replace the standard default value in the event that the current theme specifies that it
 * is a dark theme. Themes are used to specify the application's {@link LookAndFeel}, whether or
 * not it is dark, and any customized values for colors, fonts, or icons. There are several 
 * "built-in" themes, one for each supported {@link LookAndFeel}, but additional themes can
 * be defined and stored in the users application home directory as a <name>.theme file. 
 * 
 */
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

	/**
	 * Initialized the Theme and its values for the application.
	 */
	public static void initialize() {
		isInitialized = true;
		installFlatLookAndFeels();
		loadThemeDefaults();
		setTheme(getThemeFromPreferences());
//		LookAndFeelUtils.installGlobalOverrides();
	}

	/**
	 * Reloads the defaults from all the discoverable theme.property files.
	 */
	public static void reloadGhidraDefaults() {
		loadThemeDefaults();
		buildCurrentValues();
		lookAndFeelManager.resetAll(javaDefaults);
		notifyThemeChanged(new AllValuesChangedThemeEvent(false));
	}

	/**
	 * Restores all the current application back to the values as specified by the active theme.
	 * In other words, reverts any changes to the active theme that haven't been saved.
	 */
	public static void restoreThemeValues() {
		buildCurrentValues();
		lookAndFeelManager.resetAll(javaDefaults);
		notifyThemeChanged(new AllValuesChangedThemeEvent(false));
	}

	/**
	 * Sets the application's active theme to the given theme.
	 * @param theme the theme to make active
	 */
	public static void setTheme(GTheme theme) {
		if (theme.hasSupportedLookAndFeel()) {
			activeTheme = theme;
			LafType lookAndFeel = theme.getLookAndFeelType();
			lookAndFeelManager = lookAndFeel.getLookAndFeelManager();
			try {
				lookAndFeelManager.installLookAndFeel();
				notifyThemeChanged(new AllValuesChangedThemeEvent(true));
				saveThemeToPreferences(theme);
			}
			catch (Exception e) {
				Msg.error(Gui.class, "Error setting LookAndFeel: " + lookAndFeel.getName(), e);
			}
		}
	}

	/**
	 * Adds the given theme to set of all themes.
	 * @param newTheme the theme to add
	 */
	public static void addTheme(GTheme newTheme) {
		loadThemes();
		allThemes.remove(newTheme);
		allThemes.add(newTheme);
	}

	/**
	 * Removes the theme from the set of all themes. Also, if the theme has an associated
	 * file, the file will be deleted.
	 * @param theme the theme to delete
	 */
	public static void deleteTheme(GTheme theme) {
		File file = theme.getFile();
		if (file != null) {
			file.delete();
		}
		if (allThemes != null) {
			allThemes.remove(theme);
		}
	}

	/**
	 * Returns a set of all known themes.
	 * @return a set of all known themes.
	 */
	public static Set<GTheme> getAllThemes() {
		loadThemes();
		return new HashSet<>(allThemes);
	}

	/**
	 * Returns a set of all known themes that are supported on the current platform.
	 * @return a set of all known themes that are supported on the current platform.
	 */
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

	/**
	 * Returns the active theme.
	 * @return the active theme.
	 */
	public static GTheme getActiveTheme() {
		return activeTheme;
	}

	/**
	 * Returns the {@link LafType} for the currently active {@link LookAndFeel}
	 * @return the {@link LafType} for the currently active {@link LookAndFeel}
	 */
	public static LafType getLookAndFeelType() {
		return activeTheme.getLookAndFeelType();
	}

	/**
	 * Returns the known theme that has the given name.
	 * @param themeName the name of the theme to retrieve
	 * @return the known theme that has the given name
	 */
	public static GTheme getTheme(String themeName) {
		Optional<GTheme> first =
			getAllThemes().stream().filter(t -> t.getName().equals(themeName)).findFirst();
		return first.orElse(null);
	}

	/**
	 * Returns a {@link GThemeValueMap} of all current theme values.
	 * @return a {@link GThemeValueMap} of all current theme values.
	 */
	public static GThemeValueMap getAllValues() {
		return new GThemeValueMap(currentValues);
	}

	/**
	 * Returns a {@link GThemeValueMap} contains all values that differ from the default
	 * values (values defined by the {@link LookAndFeel} or in the theme.properties files.
	 * @return a {@link GThemeValueMap} contains all values that differ from the defaults.
	 */
	public static GThemeValueMap getNonDefaultValues() {
		return currentValues.getChangedValues(getDefaults());
	}

	/**
	 * Saves the current theme choice to {@link Preferences}.
	 * @param theme the theme to remember in {@link Preferences}
	 */
	public static void saveThemeToPreferences(GTheme theme) {
		Preferences.setProperty(THEME_PREFFERENCE_KEY, theme.getThemeLocater());
		Preferences.store();
	}

	/**
	 * Returns the current {@link Font} associated with the given id.
	 * @param id the id for the desired font
	 * @return the current {@link Font} associated with the given id.
	 */
	public static Font getFont(String id) {
		FontValue font = currentValues.getFont(id);
		if (font == null) {
			Throwable t = getFilteredTrace();

			Msg.error(Gui.class, "No font value registered for: " + id, t);
			return null;
		}
		return font.get(currentValues);
	}

	/**
	 * Returns the actual direct color for the id, not a GColor. Will output an error message if
	 * the id can't be resolved.
	 * @param id the id to get the direct color for
	 * @return the actual direct color for the id, not a GColor
	 */
	public static Color getRawColor(String id) {
		return getRawColor(id, true);
	}

	/**
	 * Updates the current value for the font id in the newValue
	 * @param newValue the new {@link FontValue} to install in the current values.
	 */
	public static void setFont(FontValue newValue) {
		FontValue currentValue = currentValues.getFont(newValue.getId());
		if (newValue.equals(currentValue)) {
			return;
		}
		updateChangedValuesMap(currentValue, newValue);

		currentValues.addFont(newValue);
		notifyThemeChanged(new FontChangedThemeEvent(currentValues, newValue));

		// update all java LookAndFeel fonts affected by this changed
		String id = newValue.getId();
		Set<String> affectedJavaFontIds = findAffectedJavaFontIds(id);
		Font newFont = newValue.get(currentValues);
		lookAndFeelManager.updateFonts(id, affectedJavaFontIds, newFont);
	}

	/**
	 * Updates the current color for the given id.
	 * @param id the color id to update to the new color
	 * @param color the new color for the id
	 */
	public static void setColor(String id, Color color) {
		setColor(new ColorValue(id, color));
	}

	/**
	 * Updates the current value for the color id in the newValue
	 * @param newValue the new {@link ColorValue} to install in the current values.
	 */
	public static void setColor(ColorValue newValue) {
		ColorValue currentValue = currentValues.getColor(newValue.getId());
		if (newValue.equals(currentValue)) {
			return;
		}
		updateChangedValuesMap(currentValue, newValue);
		currentValues.addColor(newValue);
		notifyThemeChanged(new ColorChangedThemeEvent(currentValues, newValue));

		// now update the ui
		lookAndFeelManager.updateColors();
	}

	/**
	 * Updates the current {@link Icon} for the given id.
	 * @param id the icon id to update to the new icon
	 * @param icon the new {@link Icon} for the id
	 */
	public static void setIcon(String id, Icon icon) {
		setIcon(new IconValue(id, icon));
	}

	/**
	 * Updates the current value for the {@link Icon} id in the newValue
	 * @param newValue the new {@link IconValue} to install in the current values.
	 */
	public static void setIcon(IconValue newValue) {
		IconValue currentValue = currentValues.getIcon(newValue.getId());
		if (newValue.equals(currentValue)) {
			return;
		}
		updateChangedValuesMap(currentValue, newValue);

		currentValues.addIcon(newValue);
		notifyThemeChanged(new IconChangedThemeEvent(currentValues, newValue));

		// now update the ui
		// update all java LookAndFeel icons affected by this changed
		String id = newValue.getId();
		Set<String> affectedJavaIconIds = findAffectedJavaIconIds(id);
		Icon newIcon = newValue.get(currentValues);
		lookAndFeelManager.updateIcons(id, affectedJavaIconIds, newIcon);
	}

	/**
	 * gets a UIResource version of the GColor for the given id. Using this method ensures that
	 * the same instance is used for a given id. This combats some poor code in some of the 
	 * {@link LookAndFeel}s where the use == in some places to test for equals.
	 * @param id the id to get a GColorUIResource for
	 * @return a GColorUIResource for the given id
	 */
	public static GColorUIResource getGColorUiResource(String id) {
		GColorUIResource gColor = gColorMap.get(id);
		if (gColor == null) {
			gColor = new GColorUIResource(id);
			gColorMap.put(id, gColor);
		}
		return gColor;
	}

	/**
	 * gets a UIResource version of the GIcon for the given id. Using this method ensures that
	 * the same instance is used for a given id. This combats some poor code in some of the 
	 * {@link LookAndFeel}s where the use == in some places to test for equals.
	 * @param id the id to get a {@link GIconUIResource} for
	 * @return a GIconUIResource for the given id
	 */
	public static GIconUIResource getGIconUiResource(String id) {

		GIconUIResource gIcon = gIconMap.get(id);
		if (gIcon == null) {
			gIcon = new GIconUIResource(id);
			gIconMap.put(id, gIcon);
		}
		return gIcon;
	}

	/**
	 * Sets the map of JavaDefaults defined by the current {@link LookAndFeel}.
	 * @param map the default theme values defined by the {@link LookAndFeel}
	 */
	public static void setJavaDefaults(GThemeValueMap map) {
		javaDefaults = fixupJavaDefaultsInheritence(map);
		buildCurrentValues();
		GColor.refreshAll();
		GIcon.refreshAll();
	}

	/**
	 * Attempts to restore the relationships between various theme values that derive from
	 * other theme values as defined in {@link BasicLookAndFeel}
	 * @param map the map of value ids to its inherited id
	 * @return a fixed up version of the given map with relationships restored where possible
	 */
	public static GThemeValueMap fixupJavaDefaultsInheritence(GThemeValueMap map) {
		JavaColorMapping.fixupJavaDefaultsInheritence(map);
		JavaFontMapping.fixupJavaDefaultsInheritence(map);
		return map;
	}

	/**
	 * Returns the {@link GThemeValueMap} containing all the default theme values defined by the
	 * current {@link LookAndFeel}.
	 * @return  the {@link GThemeValueMap} containing all the default theme values defined by the
	 * current {@link LookAndFeel}
	 */
	public static GThemeValueMap getJavaDefaults() {
		GThemeValueMap map = new GThemeValueMap();
		map.load(javaDefaults);
		return map;
	}

	/**
	 * Returns the {@link GThemeValueMap} containing all the dark default values defined
	 * in theme.properties files. Note that dark defaults includes light defaults that haven't
	 * been overridden by a dark default with the same id.
	 * @return the {@link GThemeValueMap} containing all the dark values defined in 
	 * theme.properties files
	 */
	public static GThemeValueMap getGhidraDarkDefaults() {
		GThemeValueMap map = new GThemeValueMap(ghidraLightDefaults);
		map.load(ghidraDarkDefaults);
		return map;
	}

	/**
	 * Returns the {@link GThemeValueMap} containing all the standard default values defined
	 * in theme.properties files. 
	 * @return the {@link GThemeValueMap} containing all the standard values defined in 
	 * theme.properties files
	 */
	public static GThemeValueMap getGhidraLightDefaults() {
		GThemeValueMap map = new GThemeValueMap(ghidraLightDefaults);
		return map;
	}

	/**
	 * Returns a {@link GThemeValueMap} containing all default values for the current theme. It
	 * is a combination of application defined defaults and java {@link LookAndFeel} defaults.
	 * @return the current set of defaults.
	 */
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

	/**
	 * Adds a {@link ThemeListener} to be notified of theme changes.
	 * @param listener the listener to be notified
	 */
	public static void addThemeListener(ThemeListener listener) {
		themeListeners.add(listener);
	}

	/**
	 * Removes the given {@link ThemeListener} from the list of listeners to be notified of
	 * theme changes.
	 * @param listener the listener to be removed
	 */
	public static void removeThemeListener(ThemeListener listener) {
		themeListeners.add(listener);
	}

	/**
	 * Returns the default theme for the current platform.
	 * @return the default theme for the current platform.
	 */
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

	/**
	 * Returns true if there are any unsaved changes to the current theme.
	 * @return true if there are any unsaved changes to the current theme.
	 */
	public static boolean hasThemeChanges() {
		return !changedValuesMap.isEmpty();
	}

	/**
	 * Returns the actual direct color for the id, not a GColor. 
	 * @param id the id to get the direct color for
	 * @param validate if true, will output an error if the id can't be resolved at this time
	 * @return the actual direct color for the id, not a GColor
	 */
	public static Color getRawColor(String id, boolean validate) {
		ColorValue color = currentValues.getColor(id);

		if (color == null) {
			if (validate && isInitialized) {
				Throwable t = getFilteredTrace();
				Msg.error(Gui.class, "No color value registered for: " + id, t);
			}
			return Color.CYAN;
		}
		return color.get(currentValues);
	}

	/**
	 * Returns the actual direct icon for the id, not a GIcon. 
	 * @param id the id to get the direct icon for
	 * @param validate if true, will output an error if the id can't be resolved at this time
	 * @return the actual direct icon for the id, not a GIcon
	 */
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

	/**
	 * Returns a darker version of the given color or brighter if the current theme is dark.
	 * @param color the color to get a darker version of
	 * @return a darker version of the given color or brighter if the current theme is dark
	 */
	public static Color darker(Color color) {
		if (activeTheme.useDarkDefaults()) {
			return color.brighter();
		}
		return color.darker();
	}

	/**
	 * Returns a brighter version of the given color or darker if the current theme is dark.
	 * @param color the color to get a brighter version of
	 * @return a brighter version of the given color or darker if the current theme is dark
	 */
	public static Color brighter(Color color) {
		if (activeTheme.useDarkDefaults()) {
			return color.darker();
		}
		return color.brighter();
	}

	// for testing
	public static void setPropertiesLoader(ThemePropertiesLoader loader) {
		themePropertiesLoader = loader;
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

	private static void notifyThemeChanged(ThemeEvent event) {
		for (ThemeListener listener : themeListeners) {
			listener.themeChanged(event);
		}
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
			return new ThemeReader(file).readTheme();
		}
		catch (IOException e) {
			Msg.error(Gui.class, "Could not load theme from file: " + file.getAbsolutePath(), e);
		}
		return null;
	}

	private static Collection<DiscoverableGTheme> findDiscoverableThemes() {
		return ClassSearcher.getInstances(DiscoverableGTheme.class);
	}

	private static GTheme getThemeFromPreferences() {
		String themeId = Preferences.getProperty(THEME_PREFFERENCE_KEY, "Default", true);
		if (themeId.startsWith(GTheme.FILE_PREFIX)) {
			String filename = themeId.substring(GTheme.FILE_PREFIX.length());
			try {
				return new ThemeReader(new File(filename)).readTheme();
			}
			catch (IOException e) {
				Msg.showError(GTheme.class, null, "Can't Load Previous Theme",
					"Error loading theme file: " + filename, e);
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

	private static Set<String> findAffectedJavaFontIds(String id) {
		Set<String> affectedIds = new HashSet<>();
		List<FontValue> fonts = javaDefaults.getFonts();
		for (FontValue fontValue : fonts) {
			String fontId = fontValue.getId();
			FontValue currentFontValue = currentValues.getFont(fontId);
			if (fontId.equals(id) || currentFontValue.inheritsFrom(id, currentValues)) {
				affectedIds.add(fontId);
			}
		}
		return affectedIds;
	}

	private static Set<String> findAffectedJavaIconIds(String id) {
		Set<String> affectedIds = new HashSet<>();
		List<IconValue> icons = javaDefaults.getIcons();
		for (IconValue iconValue : icons) {
			String iconId = iconValue.getId();
			if (iconId.equals(id) || iconValue.inheritsFrom(id, currentValues)) {
				affectedIds.add(iconId);
			}
		}
		return affectedIds;
	}

}
